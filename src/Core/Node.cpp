// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Node.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <iostream>
#include "Config.hpp"
#include "CryptoNoteTools.hpp"
#include "TransactionBuilder.hpp"
#include "TransactionExtra.hpp"
#include "common/Base58.hpp"
#include "common/JsonValue.hpp"
#include "http/Client.hpp"
#include "http/Server.hpp"
#include "platform/PathTools.hpp"
#include "platform/PreventSleep.hpp"
#include "platform/Time.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "version.hpp"

using namespace cn;

Node::Node(logging::ILogger &log, const Config &config, BlockChainState &block_chain)
    : m_block_chain(block_chain)
    , m_config(config)
    , m_block_chain_was_far_behind(true)
    , m_log(log, "Node")
    , m_peer_db(log, config, "peer_db")
    , m_p2p(log, config, m_peer_db, std::bind(&Node::client_factory, this, _1))
    , multicast(config.multicast_address, config.multicast_port, std::bind(&Node::on_multicast, this, _1, _2, _3))
    , m_multicast_timer(std::bind(&Node::send_multicast, this))
    , m_start_time(m_p2p.get_local_time())
    , m_commit_timer(std::bind(&Node::db_commit, this))
    , log_request_timestamp(std::chrono::steady_clock::now())
    , log_response_timestamp(std::chrono::steady_clock::now())
    , m_pow_checker(block_chain.get_currency(), platform::EventLoop::current()) {
	const std::string old_path = platform::get_default_data_directory(CRYPTONOTE_NAME);
	const std::string new_path = config.get_data_folder();

	if (!config.bytecoind_bind_ip.empty() && config.bytecoind_bind_port != 0)
		m_api = std::make_unique<http::Server>(config.bytecoind_bind_ip, config.bytecoind_bind_port,
		    std::bind(&Node::on_api_http_request, this, _1, _2, _3),
		    std::bind(&Node::on_api_http_disconnect, this, _1));

	m_commit_timer.once(float(m_config.db_commit_period_blockchain));
	advance_long_poll();
	send_multicast();
}

Node::~Node() {}  // we have unique_ptr to incomplete type

void Node::send_multicast() {
	if (!m_config.use_multicast())
		return;
	//	std::cout << "sending multicast about node listening on port=" << m_config.p2p_external_port << std::endl;
	BinaryArray ha = P2PProtocolBasic::create_multicast_announce(
	    m_config.network_id, m_block_chain.get_currency().genesis_block_hash, m_config.p2p_external_port);
	platform::UDPMulticast::send(m_config.multicast_address, m_config.multicast_port, ha.data(), ha.size());
	m_multicast_timer.once(m_config.multicast_period);
}

void Node::on_multicast(const std::string &addr, const unsigned char *data, size_t size) {
	if (!m_config.use_multicast())
		return;
	NetworkAddress na;
	na.port = P2PProtocolBasic::parse_multicast_announce(
	    data, size, m_config.network_id, m_block_chain.get_currency().genesis_block_hash);
	if (!na.port)
		return;
	if (common::parse_ip_address(addr, &na.ip)) {
		if (m_peer_db.add_incoming_peer(na, m_p2p.get_local_time()))
			m_log(logging::INFO) << "Adding peer from multicast announce addr=" << na << std::endl;
	}
	// We do not receive multicast from loopback, so we just guess peer could be from localhost
	if (common::parse_ip_address("127.0.0.1", &na.ip)) {
		if (m_peer_db.add_incoming_peer(na, m_p2p.get_local_time()))
			m_log(logging::INFO) << "Adding local peer from multicast announce addr=" << na << std::endl;
	}
	m_p2p.peers_updated();
}

void Node::db_commit() {
	m_block_chain.db_commit();
	m_commit_timer.once(float(m_config.db_commit_period_blockchain));
}

void Node::remove_chain_block(std::map<Hash, DownloadInfo>::iterator it) {
	invariant(it->second.chain_counter > 0, "");
	it->second.chain_counter -= 1;
	if (it->second.chain_counter == 0 && !it->second.preparing)
		chain_blocks.erase(it);
}

void Node::advance_all_downloads() {
	for (auto &&who : m_broadcast_protocols)
		who->advance_blocks();
}

bool Node::on_idle() {
	auto idle_start     = std::chrono::steady_clock::now();
	Hash was_top_bid    = m_block_chain.get_tip_bid();
	bool on_idle_result = false;
	if (m_block_chain.get_tip_height() >= m_block_chain.internal_import_known_height()) {
		for (size_t s = 0; s != 10; ++s) {
			bool on_idle_result_s = false;
			std::vector<P2PProtocolBytecoin *> bp_copy{m_broadcast_protocols.begin(), m_broadcast_protocols.end()};
			// We need bp_copy because on_idle can disconnect, modifying m_broadcast_protocols
			for (auto &&who : bp_copy)
				on_idle_result_s = who->on_idle(idle_start) | on_idle_result_s;
			if (!on_idle_result_s)
				break;
			on_idle_result = true;
		}
	}
	if (m_block_chain.get_tip_height() < m_block_chain.internal_import_known_height())
		m_block_chain.internal_import();
	if (m_block_chain.get_tip_bid() != was_top_bid) {
		advance_long_poll();
	}
	advance_all_downloads();
	return on_idle_result;
}

bool Node::check_trust(const p2p::ProofOfTrust &tr) {
	Timestamp local_time = platform::now_unix_timestamp();
	Timestamp time_delta = local_time > tr.time ? local_time - tr.time : tr.time - local_time;

	if (time_delta > 24 * 60 * 60)
		return false;
	if (m_last_stat_request_time >= tr.time)
		return false;
	if (m_p2p.get_unique_number() != tr.peer_id)
		return false;

	Hash h = tr.get_hash();
	if (!crypto::check_signature(h, m_config.trusted_public_key, tr.sign))
		return false;
	m_last_stat_request_time = tr.time;
	return true;
}

void Node::advance_long_poll() {
	const auto now = m_p2p.get_local_time();
	if (!m_prevent_sleep && m_block_chain.get_tip().timestamp < now - 86400)
		m_prevent_sleep = std::make_unique<platform::PreventSleep>("Downloading blockchain");
	if (m_prevent_sleep &&
	    m_block_chain.get_tip().timestamp > now - m_block_chain.get_currency().block_future_time_limit * 2)
		m_prevent_sleep = nullptr;
	if (m_long_poll_http_clients.empty())
		return;
	const api::cnd::GetStatus::Response resp = create_status_response();

	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();) {
		const bool method_status = lit->original_json_request.get_method() == api::cnd::GetStatus::method() ||
		                           lit->original_json_request.get_method() == api::cnd::GetStatus::method2();
		if (!resp.ready_for_longpoll(lit->original_get_status)) {
			++lit;
			continue;
		}
		const common::JsonValue &jid = lit->original_json_request.get_id().get();
		http::ResponseBody last_http_response;
		last_http_response.r.headers.push_back({"Content-Type", "application/json; charset=utf-8"});
		last_http_response.r.status             = 200;
		last_http_response.r.http_version_major = lit->original_request.r.http_version_major;
		last_http_response.r.http_version_minor = lit->original_request.r.http_version_minor;
		last_http_response.r.keep_alive         = lit->original_request.r.keep_alive;
		if (method_status) {
			last_http_response.set_body(json_rpc::create_response_body(resp, jid));
		} else {
			try {
				api::cnd::GetBlockTemplate::Request gbt_req;
				lit->original_json_request.load_params(gbt_req);
				api::cnd::GetBlockTemplate::Response gbt_res;
				getblocktemplate(gbt_req, gbt_res);
				last_http_response.set_body(json_rpc::create_response_body(gbt_res, jid));
			} catch (const json_rpc::Error &err) {
				last_http_response.set_body(json_rpc::create_error_response_body(err, jid));
			} catch (const std::exception &e) {
				json_rpc::Error json_err(json_rpc::INTERNAL_ERROR, common::what(e));
				last_http_response.set_body(json_rpc::create_error_response_body(json_err, jid));
			}
		}
		lit->original_who->write(std::move(last_http_response));
		lit = m_long_poll_http_clients.erase(lit);
	}
}

static const std::string beautiful_index_start =
    R"(<html><head><meta http-equiv='refresh' content='30'/></head><body><table valign="middle"><tr><td width="30px">
<p><img src="data:image/png;base64,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" style="width: 30px;"></p></td><td>)" CRYPTONOTE_NAME R"(d &bull; version
)";
static const std::string beautiful_index_finish = " </td></tr></table></body></html>";
static const std::string robots_txt             = "User-agent: *\r\nDisallow: /";

bool Node::on_api_http_request(http::Client *who, http::RequestBody &&request, http::ResponseBody &response) {
	response.r.add_headers_nocache();
	if (request.r.uri == "/robots.txt") {
		response.r.headers.push_back({"Content-Type", "text/plain; charset=UTF-8"});
		response.r.status = 200;
		response.set_body(std::string(robots_txt));
		return true;
	}
	bool good_auth =
	    m_config.bytecoind_authorization.empty() || request.r.basic_authorization == m_config.bytecoind_authorization;
	bool good_auth_private = m_config.bytecoind_authorization_private.empty() ||
	                         request.r.basic_authorization == m_config.bytecoind_authorization_private;
	if (!good_auth && !good_auth_private)  // Private methods will check for private authorization again
		throw http::ErrorAuthorization("Blockchain");
	if (request.r.uri == "/" || request.r.uri == "/index.html") {
		response.r.headers.push_back({"Content-Type", "text/html; charset=UTF-8"});
		response.r.status = 200;
		auto stat         = create_status_response();
		float sync_precantage = static_cast<int>(((stat.top_block_height/(stat.top_known_block_height/100)))*100+0.5) / 100.0;
		auto body = beautiful_index_start + app_version() + " &bull; " + m_config.net + "net &bull; sync status " +
		            common::to_string(stat.top_block_height) + "/" + common::to_string(stat.top_known_block_height) + " (" +common::to_string(sync_precantage) + " %)" +
		            beautiful_index_finish;
		if (m_config.net != "main")
			boost::replace_all(body, "#f04086", "#00afa5");
		response.set_body(std::move(body));
		return true;
	}
	if (request.r.uri == api::cnd::url()) {
		if (!on_json_rpc(who, std::move(request), response))
			return false;
		response.r.status = 200;
		return true;
	}
	if (request.r.uri == api::cnd::binary_url()) {
		if (!on_binary_rpc(who, std::move(request), response))
			return false;
		response.r.status = 200;
		return true;
	}
	response.r.status = 404;
	response.set_body("<html><body>404 Not Found</body></html>");
	return true;
}

void Node::on_api_http_disconnect(http::Client *who) {
	for (auto lit = m_long_poll_http_clients.begin(); lit != m_long_poll_http_clients.end();)
		if (lit->original_who == who)
			lit = m_long_poll_http_clients.erase(lit);
		else
			++lit;
}

const std::unordered_map<std::string, Node::BINARYRPCHandlerFunction> Node::m_binaryrpc_handlers = {
    {api::cnd::SyncBlocks::bin_method(), json_rpc::make_binary_member_method(&Node::on_sync_blocks)},
    {api::cnd::SyncMemPool::bin_method(), json_rpc::make_binary_member_method(&Node::on_sync_mempool)}};

std::unordered_map<std::string, Node::JSONRPCHandlerFunction> Node::m_jsonrpc_handlers = {
    {api::cnd::GetLastBlockHeaderLegacy::method(), json_rpc::make_member_method(&Node::on_get_last_block_header)},
    {api::cnd::GetBlockHeaderByHashLegacy::method(), json_rpc::make_member_method(&Node::on_get_block_header_by_hash)},
    {api::cnd::GetBlockHeaderByHeightLegacy::method(),
        json_rpc::make_member_method(&Node::on_get_block_header_by_height)},
    {api::cnd::GetBlockTemplate::method(), json_rpc::make_member_method(&Node::on_getblocktemplate)},
    {api::cnd::GetBlockTemplate::method_legacy(), json_rpc::make_member_method(&Node::on_getblocktemplate)},
    {api::cnd::GetCurrencyId::method(), json_rpc::make_member_method(&Node::on_get_currency_id)},
    {api::cnd::GetCurrencyId::method_legacy(), json_rpc::make_member_method(&Node::on_get_currency_id)},
    {api::cnd::SubmitBlock::method(), json_rpc::make_member_method(&Node::on_submitblock)},
    {api::cnd::SubmitBlockLegacy::method(), json_rpc::make_member_method(&Node::on_submitblock_legacy)},
    {api::cnd::GetRandomOutputs::method(), json_rpc::make_member_method(&Node::on_get_random_outputs)},
    {api::cnd::GetStatus::method(), json_rpc::make_member_method(&Node::on_get_status)},
    {api::cnd::GetStatus::method2(), json_rpc::make_member_method(&Node::on_get_status)},
    {api::cnd::GetStatistics::method(), json_rpc::make_member_method(&Node::on_get_statistics)},
    {api::cnd::GetArchive::method(), json_rpc::make_member_method(&Node::on_get_archive)},
    {api::cnd::SendTransaction::method(), json_rpc::make_member_method(&Node::on_send_transaction)},
    {api::cnd::CheckSendproof::method(), json_rpc::make_member_method(&Node::on_check_sendproof)},
    {api::cnd::SyncBlocks::method(), json_rpc::make_member_method(&Node::on_sync_blocks)},
    {api::cnd::GetRawBlock::method(), json_rpc::make_member_method(&Node::on_get_raw_block)},
    {api::cnd::GetBlockHeader::method(), json_rpc::make_member_method(&Node::on_get_block_header)},
    {api::cnd::GetRawTransaction::method(), json_rpc::make_member_method(&Node::on_get_raw_transaction)},
    {api::cnd::SyncMemPool::method(), json_rpc::make_member_method(&Node::on_sync_mempool)}};

bool Node::on_get_random_outputs(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetRandomOutputs::Request &&request, api::cnd::GetRandomOutputs::Response &response) {
	Height confirmed_height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
	    request.confirmed_height_or_depth, m_block_chain.get_tip_height(), true, false);
	api::BlockHeader confirmed_header = m_block_chain.get_tip();
	Hash confirmed_hash;
	invariant(m_block_chain.get_chain(confirmed_height_or_depth, &confirmed_hash), "");
	invariant(m_block_chain.get_header(confirmed_hash, &confirmed_header), "");
	for (uint64_t amount : request.amounts) {
		auto random_outputs =
		    m_block_chain.get_random_outputs(confirmed_header.major_version, amount, request.output_count,
		        confirmed_height_or_depth, confirmed_header.timestamp, confirmed_header.timestamp_median);
		auto &outs = response.outputs[amount];
		outs.insert(outs.end(), random_outputs.begin(), random_outputs.end());
	}
	return true;
}

api::cnd::GetStatus::Response Node::create_status_response() const {
	api::cnd::GetStatus::Response res;
	res.top_block_height       = m_block_chain.get_tip_height();
	res.top_known_block_height = res.top_block_height;
	for (auto &&gc : m_broadcast_protocols)
		res.top_known_block_height = std::max(res.top_known_block_height, gc->get_peer_sync_data().current_height);
	res.top_known_block_height =
	    std::max<Height>(res.top_known_block_height, m_block_chain.internal_import_known_height());
	for (auto &&pb : m_broadcast_protocols)
		if (pb->is_incoming())
			res.incoming_peer_count += 1;
		else
			res.outgoing_peer_count += 1;
	api::BlockHeader tip                 = m_block_chain.get_tip();
	res.top_block_hash                   = m_block_chain.get_tip_bid();
	res.top_block_timestamp              = tip.timestamp;
	res.top_block_timestamp_median       = tip.timestamp_median;
	res.top_block_difficulty             = tip.difficulty;
	res.top_block_cumulative_difficulty  = tip.cumulative_difficulty;
	res.recommended_fee_per_byte         = m_block_chain.get_currency().coin() / 1000000;  // TODO - calculate
	res.recommended_max_transaction_size = m_block_chain.get_currency().get_recommended_max_transaction_size();
	res.transaction_pool_version         = m_block_chain.get_tx_pool_version();
	return res;
}

void Node::broadcast(P2PProtocolBytecoin *exclude, const BinaryArray &data) {
	for (auto &&p : m_broadcast_protocols)
		if (p != exclude)
			p->P2PProtocol::send(BinaryArray(data));  // Move is impossible here
}
void Node::broadcast(P2PProtocolBytecoin *exclude, const BinaryArray &data_v1, const BinaryArray &data_v4) {
	for (auto &&p : m_broadcast_protocols)
		if (p != exclude)
			p->P2PProtocol::send(BinaryArray(
			    p->get_peer_version() >= P2PProtocolVersion::AMETHYST ? data_v4 : data_v1));  // Move is impossible here
}

bool Node::on_get_status(http::Client *who, http::RequestBody &&raw_request, json_rpc::Request &&raw_js_request,
    api::cnd::GetStatus::Request &&req, api::cnd::GetStatus::Response &res) {
	res = create_status_response();
	if (!res.ready_for_longpoll(req)) {
		//		m_log(logging::INFO) << "on_get_status will long poll, json="
		// << raw_request.body << std::endl;
		LongPollClient lpc;
		lpc.original_who          = who;
		lpc.original_request      = raw_request;
		lpc.original_json_request = std::move(raw_js_request);
		lpc.original_get_status   = req;
		m_long_poll_http_clients.push_back(lpc);
		return false;
	}
	return true;
}

api::cnd::GetStatistics::Response Node::create_statistics_response(const api::cnd::GetStatistics::Request &req) const {
	api::cnd::GetStatistics::Response res;
	res.peer_id = m_p2p.get_unique_number();
	if (req.need_connected_peers) {
		for (auto &&p : m_broadcast_protocols) {
			ConnectionDesc desc;
			desc.address               = p->get_address();
			desc.is_incoming           = p->is_incoming();
			desc.p2p_version           = p->get_peer_version();
			desc.peer_id               = p->get_peer_unique_number();
			desc.top_block_desc.hash   = p->get_peer_sync_data().top_id;
			desc.top_block_desc.height = p->get_peer_sync_data().current_height;
			res.connected_peers.push_back(desc);
		}
	}
	if (req.need_peer_lists) {
		res.peer_list_gray = m_peer_db.get_peer_list_gray();
		res.peer_list_gray = m_peer_db.get_peer_list_white();
	}
	res.platform           = platform::get_platform_name();
	res.version            = cn::app_version();
	res.net                = m_config.net;
	res.genesis_block_hash = m_block_chain.get_currency().genesis_block_hash;
	res.start_time         = m_start_time;
	m_block_chain.fill_statistics(res);
	return res;
}

bool Node::on_get_statistics(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&,
    api::cnd::GetStatistics::Request &&req, api::cnd::GetStatistics::Response &res) {
	bool good_auth_private = m_config.bytecoind_authorization_private.empty() ||
	                         http_request.r.basic_authorization == m_config.bytecoind_authorization_private;
	if (!good_auth_private)
		throw http::ErrorAuthorization("Statistics");
	res = create_statistics_response(req);
	return true;
}

bool Node::on_get_archive(http::Client *, http::RequestBody &&http_request, json_rpc::Request &&,
    api::cnd::GetArchive::Request &&req, api::cnd::GetArchive::Response &resp) {
	bool good_auth_private = m_config.bytecoind_authorization_private.empty() ||
	                         http_request.r.basic_authorization == m_config.bytecoind_authorization_private;
	if (!good_auth_private)
		throw http::ErrorAuthorization("Archive");
	m_block_chain.read_archive(std::move(req), resp);
	return true;
}

// mixed_public_keys can be null if keys not needed
void Node::fill_transaction_info(
    const TransactionPrefix &tx, api::Transaction *api_tx, std::vector<std::vector<PublicKey>> *mixed_public_keys) {
	api_tx->unlock_block_or_timestamp = tx.unlock_block_or_timestamp;
	api_tx->extra                     = tx.extra;
	api_tx->anonymity                 = std::numeric_limits<size_t>::max();
	api_tx->public_key                = extra_get_transaction_public_key(tx.extra);
	api_tx->prefix_hash               = get_transaction_prefix_hash(tx);
	api_tx->inputs_hash               = get_transaction_inputs_hash(tx);
	extra_get_payment_id(tx.extra, api_tx->payment_id);
	Amount input_amount = 0;
	for (const auto &input : tx.inputs) {
		if (input.type() == typeid(InputKey)) {
			const InputKey &in = boost::get<InputKey>(input);
			api_tx->anonymity  = std::min(api_tx->anonymity, in.output_indexes.size() - 1);
			input_amount += in.amount;
			if (mixed_public_keys)
				mixed_public_keys->push_back(m_block_chain.get_mixed_public_keys(in));
		}
	}
	Amount output_amount = get_tx_sum_outputs(tx);
	api_tx->amount       = output_amount;
	if (input_amount >= output_amount)
		api_tx->fee = input_amount - output_amount;
	if (api_tx->anonymity == std::numeric_limits<size_t>::max())
		api_tx->anonymity = 0;  // No key inputs
}

bool Node::on_sync_blocks(http::Client *, http::RequestBody &&, json_rpc::Request &&json_req,
    api::cnd::SyncBlocks::Request &&req, api::cnd::SyncBlocks::Response &res) {
	if (req.sparse_chain.empty())
		throw std::runtime_error("Empty sparse chain - must include at least 1 block (usually genesis)");
	if (req.sparse_chain.back() == Hash{})  // We allow to ask for "whatever genesis bid. Useful for explorer, etc."
		req.sparse_chain.back() = m_block_chain.get_genesis_bid();
	if (req.max_count > m_config.rpc_sync_blocks_max_count)
		req.max_count = m_config.rpc_sync_blocks_max_count;
	auto first_block_timestamp = req.first_block_timestamp < m_block_chain.get_currency().block_future_time_limit
	                                 ? 0
	                                 : req.first_block_timestamp - m_block_chain.get_currency().block_future_time_limit;
	Height full_offset = m_block_chain.get_timestamp_lower_bound_height(first_block_timestamp);
	Height start_height;
	std::vector<Hash> subchain =
	    m_block_chain.get_sync_headers_chain(req.sparse_chain, &start_height, req.max_count + 1);
	// Will throw if no common subchain
	if (!subchain.empty() && start_height != 0) {
		subchain.erase(subchain.begin());  // Caller never needs common block she already has
		start_height += 1;                 // Except if genesis (caller knows hash, but has no block)
	} else if (subchain.size() > req.max_count) {
		subchain.pop_back();
	}
	if (full_offset >= start_height + subchain.size()) {
		start_height = full_offset;
		subchain.clear();
		while (subchain.size() < req.max_count) {
			Hash ha;
			if (!m_block_chain.get_chain(start_height + static_cast<Height>(subchain.size()), &ha))
				break;
			subchain.push_back(ha);
		}
	} else if (full_offset > start_height) {
		subchain.erase(subchain.begin(), subchain.begin() + (full_offset - start_height));
		start_height = full_offset;
	}

	res.start_height = start_height;
	res.blocks.resize(subchain.size());
	size_t total_size = 0;
	for (size_t i = 0; i != subchain.size(); ++i) {
		const auto &bhash = subchain[i];
		auto &res_block   = res.blocks[i];
		invariant(
		    m_block_chain.get_header(bhash, &res_block.header), "Block header must be there, but it is not there");

		//		BlockChainState::BlockGlobalIndices output_indexes;
		// if (res.blocks[i].header.timestamp >= req.first_block_timestamp) //
		// commented out becuase empty Block cannot be serialized
		{
			RawBlock rb;
			invariant(m_block_chain.get_block(bhash, &rb), "Block must be there, but it is not there");
			Block block(rb);
			res_block.transactions.resize(block.transactions.size() + 1);
			res_block.transactions.at(0).hash = get_transaction_hash(block.header.base_transaction);
			res_block.transactions.at(0).size = seria::binary_size(block.header.base_transaction);
			if (req.need_redundant_data) {
				fill_transaction_info(block.header.base_transaction, &res_block.transactions.at(0), nullptr);
				res_block.transactions.at(0).block_height = start_height + static_cast<Height>(i);
				res_block.transactions.at(0).block_hash   = bhash;
				res_block.transactions.at(0).coinbase     = true;
				res_block.transactions.at(0).timestamp    = block.header.timestamp;
			}
			res_block.raw_header = std::move(block.header);
			res_block.raw_transactions.reserve(block.transactions.size());
			for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
				res_block.transactions.at(tx_index + 1).hash = res_block.raw_header.transaction_hashes.at(tx_index);
				res_block.transactions.at(tx_index + 1).size = rb.transactions.at(tx_index).size();
				if (req.need_redundant_data) {
					fill_transaction_info(
					    block.transactions.at(tx_index), &res_block.transactions.at(tx_index + 1), nullptr);
					res_block.transactions.at(tx_index + 1).block_height = start_height + static_cast<Height>(i);
					res_block.transactions.at(tx_index + 1).block_hash   = bhash;
					res_block.transactions.at(tx_index + 1).timestamp    = res_block.raw_header.timestamp;
				}
				res_block.raw_transactions.push_back(std::move(block.transactions.at(tx_index)));
			}
			invariant(m_block_chain.read_block_output_global_indices(bhash, &res_block.output_stack_indexes),
			    "Invariant dead - bid is in chain but blockchain has no block indices");
		}
		total_size += res_block.header.transactions_size;
		if (total_size >= req.max_size) {
			res.blocks.resize(i + 1);
			break;
		}
	}
	res.status = create_status_response();
	return true;
}

bool Node::on_sync_mempool(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::SyncMemPool::Request &&req, api::cnd::SyncMemPool::Response &res) {
	const auto &pool = m_block_chain.get_memory_state_transactions();
	for (auto &&ex : req.known_hashes)
		if (pool.count(ex) == 0)
			res.removed_hashes.push_back(ex);
	for (auto &&tx : pool)
		if (!std::binary_search(req.known_hashes.begin(), req.known_hashes.end(), tx.first)) {
			res.added_raw_transactions.push_back(tx.second.tx);
			res.added_transactions.push_back(api::Transaction{});
			if (req.need_redundant_data)
				fill_transaction_info(tx.second.tx, &res.added_transactions.back(), nullptr);
			res.added_transactions.back().hash      = tx.first;
			res.added_transactions.back().timestamp = tx.second.timestamp;
			res.added_transactions.back().amount    = tx.second.amount;
			res.added_transactions.back().fee       = tx.second.fee;
			res.added_transactions.back().size      = tx.second.binary_tx.size();
		}
	res.status = create_status_response();
	return true;
}

bool Node::on_get_block_header(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetBlockHeader::Request &&request, api::cnd::GetBlockHeader::Response &response) {
	if (request.hash != Hash{} && request.height_or_depth != std::numeric_limits<api::HeightOrDepth>::max())
		throw json_rpc::Error(
		    json_rpc::INVALID_REQUEST, "You cannot specify both hash and height_or_depth to this method");
	if (request.hash != Hash{}) {
		if (!m_block_chain.get_header(request.hash, &response.block_header))
			throw api::ErrorHashNotFound("Block not found in either main or side chains", request.hash);
	} else {
		Height height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
		    request.height_or_depth, m_block_chain.get_tip_height(), true, true);
		invariant(
		    m_block_chain.get_chain(height_or_depth, &request.hash), "");  // after fix_height it must always succeed
		invariant(m_block_chain.get_header(request.hash, &response.block_header), "");
	}
	response.orphan_status = !m_block_chain.in_chain(response.block_header.height, response.block_header.hash);
	response.depth =
	    api::HeightOrDepth(response.block_header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}
bool Node::on_get_raw_block(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetRawBlock::Request &&request, api::cnd::GetRawBlock::Response &response) {
	if (request.hash != Hash{} && request.height_or_depth != std::numeric_limits<api::HeightOrDepth>::max())
		throw json_rpc::Error(
		    json_rpc::INVALID_REQUEST, "You cannot specify both hash and height_or_depth to this method");
	if (request.hash != Hash{}) {
		if (!m_block_chain.get_header(request.hash, &response.block.header))
			throw api::ErrorHashNotFound("Block not found in either main or side chains", request.hash);
	} else {
		Height height_or_depth = api::ErrorWrongHeight::fix_height_or_depth(
		    request.height_or_depth, m_block_chain.get_tip_height(), true, true);
		invariant(
		    m_block_chain.get_chain(height_or_depth, &request.hash), "");  // after fix_height it must always succeed
		invariant(m_block_chain.get_header(request.hash, &response.block.header), "");
	}
	RawBlock rb;
	invariant(m_block_chain.get_block(request.hash, &rb), "Block must be there, but it is not there");
	Block block(rb);

	api::RawBlock &b = response.block;
	b.transactions.resize(block.transactions.size() + 1);
	b.transactions.at(0).hash = get_transaction_hash(block.header.base_transaction);
	b.transactions.at(0).size = seria::binary_size(block.header.base_transaction);
	fill_transaction_info(block.header.base_transaction, &b.transactions.at(0), nullptr);
	b.transactions.at(0).block_height = b.header.height;
	b.transactions.at(0).block_hash   = b.header.hash;
	b.transactions.at(0).coinbase     = true;
	b.transactions.at(0).timestamp    = block.header.timestamp;
	b.raw_header                      = std::move(block.header);
	b.raw_transactions.reserve(block.transactions.size());
	for (size_t tx_index = 0; tx_index != block.transactions.size(); ++tx_index) {
		b.transactions.at(tx_index + 1).hash = b.raw_header.transaction_hashes.at(tx_index);
		b.transactions.at(tx_index + 1).size = rb.transactions.at(tx_index).size();
		fill_transaction_info(block.transactions.at(tx_index), &b.transactions.at(tx_index + 1), nullptr);
		b.transactions.at(tx_index + 1).block_height = b.header.height;
		b.transactions.at(tx_index + 1).block_hash   = b.header.hash;
		b.transactions.at(tx_index + 1).timestamp    = b.raw_header.timestamp;
		b.raw_transactions.push_back(std::move(block.transactions.at(tx_index)));
	}
	m_block_chain.read_block_output_global_indices(request.hash, &b.output_stack_indexes);
	// If block not in main chain - global indices will be empty
	response.orphan_status = !m_block_chain.in_chain(b.header.height, b.header.hash);
	response.depth = api::HeightOrDepth(b.header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}

bool Node::on_get_raw_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::GetRawTransaction::Request &&req, api::cnd::GetRawTransaction::Response &res) {
	const auto &pool = m_block_chain.get_memory_state_transactions();
	auto tit         = pool.find(req.hash);
	if (tit != pool.end()) {
		res.raw_transaction = static_cast<const TransactionPrefix &>(tit->second.tx);
		fill_transaction_info(tit->second.tx, &res.transaction, &res.mixed_public_keys);
		res.transaction.fee          = tit->second.fee;
		res.transaction.hash         = req.hash;
		res.transaction.block_height = m_block_chain.get_tip_height() + 1;
		res.transaction.timestamp    = tit->second.timestamp;
		res.transaction.size         = tit->second.binary_tx.size();
		return true;
	}
	BinaryArray binary_tx;
	Transaction tx;
	size_t index_in_block = 0;
	if (m_block_chain.get_transaction(
	        req.hash, &binary_tx, &res.transaction.block_height, &res.transaction.block_hash, &index_in_block)) {
		api::BlockHeader bh;
		invariant(m_block_chain.get_header(res.transaction.block_hash, &bh, res.transaction.block_height), "");
		res.transaction.timestamp = bh.timestamp;
		res.transaction.size      = binary_tx.size();
		seria::from_binary(tx, binary_tx);
		res.raw_transaction = static_cast<const TransactionPrefix &>(tx);
		fill_transaction_info(tx, &res.transaction, &res.mixed_public_keys);
		res.transaction.coinbase = (index_in_block == 0);
		res.transaction.hash     = req.hash;
		res.transaction.fee      = get_tx_fee(res.raw_transaction);
		return true;
	}
	throw api::ErrorHashNotFound(
	    "Transaction not found in main chain or memory pool. You cannot get transactions from side chains with this method.",
	    req.hash);
}

bool Node::on_send_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::SendTransaction::Request &&request, api::cnd::SendTransaction::Response &response) {
	response.send_result = "broadcast";

	p2p::RelayTransactions::Notify msg;
	p2p::RelayTransactions::Notify msg_v4;
	//	Height conflict_height =
	//	    m_block_chain.get_currency().max_block_height;  // So will not be accidentally viewed as confirmed
	Transaction tx;
	try {
		seria::from_binary(tx, request.binary_transaction);
		const Hash tid = get_transaction_hash(tx);
		if (m_block_chain.add_transaction(tid, tx, request.binary_transaction, m_p2p.get_local_time(), "json_rpc")) {
			msg.txs.push_back(request.binary_transaction);
			TransactionDesc desc;
			desc.hash                       = tid;
			desc.size                       = request.binary_transaction.size();
			desc.fee                        = get_tx_fee(tx);
			Height newest_referenced_height = 0;
			invariant(m_block_chain.get_largest_referenced_height(tx, &newest_referenced_height), "");
			invariant(m_block_chain.get_chain(newest_referenced_height, &desc.newest_referenced_block), "");
			msg_v4.transaction_descs.push_back(desc);

			BinaryArray raw_msg    = LevinProtocol::send(msg);
			BinaryArray raw_msg_v4 = LevinProtocol::send(msg_v4);
			broadcast(nullptr, raw_msg, raw_msg_v4);
			advance_long_poll();
		}
	} catch (const ConsensusErrorOutputDoesNotExist &ex) {
		throw api::cnd::SendTransaction::Error(api::cnd::SendTransaction::WRONG_OUTPUT_REFERENCE, common::what(ex),
		    m_block_chain.get_currency().max_block_height);
	} catch (const ConsensusErrorBadOutputOrSignature &ex) {
		throw api::cnd::SendTransaction::Error(
		    api::cnd::SendTransaction::WRONG_OUTPUT_REFERENCE, common::what(ex), ex.conflict_height);
	} catch (const ConsensusErrorOutputSpent &ex) {
		throw api::cnd::SendTransaction::Error(
		    api::cnd::SendTransaction::OUTPUT_ALREADY_SPENT, common::what(ex), ex.conflict_height);
	} catch (const std::exception &ex) {
		std::throw_with_nested(api::cnd::SendTransaction::Error(
		    api::cnd::SendTransaction::INVALID_TRANSACTION_BINARY_FORMAT, common::what(ex), 0));
	}
	return true;
}

void Node::check_sendproof(const SendproofLegacy &sp, api::cnd::CheckSendproof::Response &response) const {
	BinaryArray binary_tx;
	Height height = 0;
	Hash block_hash;
	size_t index_in_block = 0;
	if (!m_block_chain.get_transaction(sp.transaction_hash, &binary_tx, &height, &block_hash, &index_in_block)) {
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::NOT_IN_MAIN_CHAIN, "Transaction is not in main chain");
	}
	Transaction tx;
	seria::from_binary(tx, binary_tx);
	const Hash message_hash = crypto::cn_fast_hash(sp.message.data(), sp.message.size());
	if (tx.version >= m_block_chain.get_currency().amethyst_transaction_version)
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION,
		    "Legacy proof cannot be used for amethyst transactions");
	AccountAddress address;
	if (!m_block_chain.get_currency().parse_account_address_string(sp.address, &address))
		throw api::ErrorAddress(
		    api::ErrorAddress::ADDRESS_FAILED_TO_PARSE, "Failed to parse sendproof address", sp.address);
	if (address.type() != typeid(AccountAddressLegacy))
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION,
		    "Transaction version too low to contain address of type other than simple");
	auto &addr              = boost::get<AccountAddressLegacy>(address);
	PublicKey tx_public_key = extra_get_transaction_public_key(tx.extra);
	if (!crypto::check_sendproof(tx_public_key, addr.V, sp.derivation, message_hash, sp.signature)) {
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::WRONG_SIGNATURE, "Proof object does not match transaction or was tampered with");
	}
	Amount total_amount = 0;
	size_t out_index    = 0;
	for (const auto &output : tx.outputs) {
		if (output.type() == typeid(OutputKey)) {
			const auto &key_output    = boost::get<OutputKey>(output);
			const PublicKey spend_key = underive_address_S(sp.derivation, out_index, key_output.public_key);
			if (spend_key == addr.S) {
				total_amount += key_output.amount;
				response.output_indexes.push_back(out_index);
			}
		}
		++out_index;
	}
	if (total_amount == 0)
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION, "No transfers found to proof address");
	response.transaction_hash = sp.transaction_hash;
	response.address          = sp.address;
	response.message          = sp.message;
	response.amount           = total_amount;
}

void Node::check_sendproof(const BinaryArray &data_inside_base58, api::cnd::CheckSendproof::Response &response) const {
	common::MemoryInputStream stream(data_inside_base58.data(), data_inside_base58.size());
	seria::BinaryInputStream ba(stream);
	ba.begin_object();
	SendproofAmethyst sp;
	try {
		seria::ser_members(sp, ba);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::FAILED_TO_PARSE, "Failed to parse proof object"));
	}
	if (sp.version < m_block_chain.get_currency().amethyst_transaction_version) {
		ba.end_object();
		if (!stream.empty())
			throw api::cnd::CheckSendproof::Error(
			    api::cnd::CheckSendproof::FAILED_TO_PARSE, "Failed to parse proof object - too many bytes");
		SendproofLegacy spk;
		spk.transaction_hash = sp.transaction_hash;
		spk.message          = sp.message;
		spk.address          = m_block_chain.get_currency().account_address_as_string(sp.address_simple);
		spk.derivation       = sp.derivation;
		spk.signature        = sp.signature;
		check_sendproof(spk, response);
		return;
	}
	BinaryArray binary_tx;
	Height height = 0;
	Hash block_hash;
	size_t index_in_block = 0;
	if (!m_block_chain.get_transaction(sp.transaction_hash, &binary_tx, &height, &block_hash, &index_in_block)) {
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::NOT_IN_MAIN_CHAIN, "Transaction is not in main chain");
	}
	Transaction tx;
	seria::from_binary(tx, binary_tx);
	if (tx.inputs.empty() || tx.inputs.at(0).type() != typeid(InputKey))
		throw api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::FAILED_TO_PARSE,
		    "Proof object invalid, because references coinbase transactions");
	if (tx.version != sp.version)
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION, "Proof version wrong for transaction version");
	const Hash tx_inputs_hash = get_transaction_inputs_hash(tx);

	const InputKey &in = boost::get<InputKey>(tx.inputs.at(0));
	TransactionPrefix fake_prefix;
	fake_prefix.version = tx.version;
	fake_prefix.inputs.push_back(in);
	RingSignatureAmethyst rsa;
	try {
		seria::ser_members(rsa, ba, fake_prefix);
	} catch (const std::exception &) {
		std::throw_with_nested(
		    api::cnd::CheckSendproof::Error(api::cnd::CheckSendproof::FAILED_TO_PARSE, "Failed to parse proof object"));
	}
	ba.end_object();
	if (!stream.empty())
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::FAILED_TO_PARSE, "Failed to parse proof object - too many bytes");

	const auto proof_body = seria::to_binary(sp);
	//	std::cout << "Proof body: " << common::to_hex(proof_body) << std::endl;
	const auto proof_prefix_hash = crypto::cn_fast_hash(proof_body);
	//	std::cout << "Proof hash: " << proof_prefix_hash << std::endl;

	std::vector<KeyImage> all_keyimages{in.key_image};
	std::vector<std::vector<PublicKey>> all_output_keys{m_block_chain.get_mixed_public_keys(in)};

	if (!crypto::check_ring_signature_amethyst(proof_prefix_hash, all_keyimages, all_output_keys, rsa)) {
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::WRONG_SIGNATURE, "Proof object does not match transaction or was tampered with");
	}
	for (size_t oi = 1; oi < sp.elements.size(); ++oi) {
		if (sp.elements.at(oi).out_index <= sp.elements.at(oi - 1).out_index)
			throw api::cnd::CheckSendproof::Error(
			    api::cnd::CheckSendproof::WRONG_SIGNATURE, "Proof object elements are not in strict ascending order");
	}
	std::reverse(sp.elements.begin(), sp.elements.end());  // pop_back instead of erase(begin)
	Amount total_amount = 0;
	boost::optional<AccountAddress> all_addresses;
	for (size_t out_index = 0; out_index != tx.outputs.size() && !sp.elements.empty(); ++out_index) {
		const auto &output = tx.outputs.at(out_index);
		if (output.type() != typeid(OutputKey))
			continue;
		const auto &key_output = boost::get<OutputKey>(output);
		if (sp.elements.back().out_index != out_index)
			continue;
		const auto &el = sp.elements.back();
		AccountAddress output_address;
		if (!TransactionBuilder::detect_not_our_output_amethyst(
		        tx_inputs_hash, el.output_seed, out_index, key_output, &output_address)) {
			throw api::cnd::CheckSendproof::Error(
			    api::cnd::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION, "Cannot underive address for proof output");
		}
		if (all_addresses && all_addresses.get() != output_address) {
			throw api::cnd::CheckSendproof::Error(
			    api::cnd::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION, "Send proof address inconsistent");
		}
		all_addresses = output_address;
		total_amount += key_output.amount;
		response.output_indexes.push_back(out_index);
		sp.elements.pop_back();
	}
	if (!sp.elements.empty())
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::WRONG_SIGNATURE, "Proof object contains excess elements");
	if (total_amount == 0 || !all_addresses)
		throw api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::ADDRESS_NOT_IN_TRANSACTION, "No transfers found to proof address");
	response.transaction_hash = sp.transaction_hash;
	response.address          = m_block_chain.get_currency().account_address_as_string(all_addresses.get());
	;
	response.message = sp.message;
	response.amount  = total_amount;
}

bool Node::on_check_sendproof(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::CheckSendproof::Request &&request, api::cnd::CheckSendproof::Response &response) {
	uint64_t utag = 0;
	BinaryArray data_inside_base58;
	if (common::base58::decode_addr(request.sendproof, &utag, &data_inside_base58)) {
		if (utag != m_block_chain.get_currency().sendproof_base58_prefix)
			throw api::cnd::CheckSendproof::Error(
			    api::cnd::CheckSendproof::FAILED_TO_PARSE, "Failed to parse proof object, wrong prefix");
		check_sendproof(data_inside_base58, response);
		return true;
	}
	SendproofLegacy sp;
	try {
		common::JsonValue jv = common::JsonValue::from_string(request.sendproof);
		seria::from_json_value(sp, jv);
	} catch (const std::exception &ex) {
		std::throw_with_nested(api::cnd::CheckSendproof::Error(
		    api::cnd::CheckSendproof::FAILED_TO_PARSE, "Failed to parse proof object ex.what=" + common::what(ex)));
	}
	check_sendproof(sp, response);
	return true;
}

void Node::submit_block(const BinaryArray &blockblob, api::BlockHeader *info) {
	BlockTemplate block_template;
	seria::from_binary(block_template, blockblob);
	RawBlock raw_block;
	try {
		if (!m_block_chain.add_mined_block(blockblob, &raw_block, info))
			return;
	} catch (const std::exception &ex) {
		throw json_rpc::Error{
		    api::cnd::SubmitBlock::BLOCK_NOT_ACCEPTED, "Block not accepted, reason=" + common::what(ex)};
	}
	for (auto who : m_broadcast_protocols)
		who->advance_transactions();
	p2p::RelayBlock::Notify msg;
	msg.b                         = std::move(raw_block);  // RawBlockLegacy{raw_block.block, raw_block.transactions};
	msg.hop                       = 1;
	msg.current_blockchain_height = m_block_chain.get_tip_height();
	msg.top_id                    = m_block_chain.get_tip_bid();
	p2p::RelayBlock::Notify msg_v4;
	msg_v4.b.block                   = msg.b.block;
	msg_v4.current_blockchain_height = msg.current_blockchain_height;
	msg_v4.top_id                    = msg.top_id;
	msg_v4.hop                       = msg.hop;

	msg.top_id = Hash{};  // TODO - uncomment after 3.4 fork. This is workaround of bug in 3.2

	BinaryArray raw_msg    = LevinProtocol::send(msg);
	BinaryArray raw_msg_v4 = LevinProtocol::send(msg_v4);
	broadcast(nullptr, raw_msg, raw_msg_v4);
	advance_long_poll();
}

bool Node::on_submitblock(http::Client *, http::RequestBody &&, json_rpc::Request &&,
    api::cnd::SubmitBlock::Request &&req, api::cnd::SubmitBlock::Response &res) {
	if (!req.cm_nonce.empty()) {
#if infinium_ALLOW_CM
		// Experimental, a bit hacky
		BlockTemplate bt;
		seria::from_binary(bt, req.blocktemplate_blob);
		bt.major_version += 1;
		bt.nonce               = req.cm_nonce;
		bt.cm_merkle_branch    = req.cm_merkle_branch;
		req.blocktemplate_blob = seria::to_binary(bt);
		//		auto body_proxy = get_body_proxy_from_template(bt);
		//		auto cm_prehash  = get_auxiliary_block_header_hash(bt, body_proxy);
		//		std::cout << "submit CM data " << body_proxy.transactions_merkle_root << " " << cm_prehash << std::endl;
#else
		throw json_rpc::Error{
		    api::cnd::SubmitBlock::BLOCK_NOT_ACCEPTED, "Block not accepted, CM mining is not supported"};
#endif
	}
	submit_block(req.blocktemplate_blob, &res.block_header);
	res.orphan_status = !m_block_chain.in_chain(res.block_header.height, res.block_header.hash);
	res.depth = api::HeightOrDepth(res.block_header.height) - api::HeightOrDepth(m_block_chain.get_tip_height()) - 1;
	return true;
}
