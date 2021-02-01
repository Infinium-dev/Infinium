// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include "CryptoNote.hpp"
#include "common/StringTools.hpp"
#include "p2p/P2pProtocolTypes.hpp"

#define CRYPTONOTE_NAME "infinium"
#ifndef CRYPTONOTE_NAME
#error CRYPTONOTE_NAME must be defined before compiling project
#endif

// All values below should only be used in code through Currency and Config classes, never directly.
// This approach allows unlimited customization through config file/command line parameters
// Never include this header into other headers
namespace cn { namespace parameters {

// Magics
const char GENESIS_COINBASE_TX_HEX[] =
    "013c01ff0000210189b02a3b9d8c676bb0715d55fa9f3c37424ebd59fec7cc964afbf05152b23f1b";
// Technically, we should not have predefined genesis block, first hard checkpoint is enough. This is bitcoin legacy.
//constexpr UUID BYTECOIN_NETWORK = common::pfh<UUID>("11100111110001011011001210110110");  // Bender's nightmare
constexpr UUID BYTECOIN_NETWORK = { { 0x12 ,0x34, 0x56, 0x78 , 0x11, 0x78 , 0x78, 0x51, 0x14, 0xAA, 0x30, 0x12, 0x19, 0x31, 0x21, 0x16} };

const Height INFINIUM_FIRST_HARDFORK                                  = 2;

const Height UPGRADE_HEIGHT_V2                                         = INFINIUM_FIRST_HARDFORK;
const Height UPGRADE_HEIGHT_V3                                         = INFINIUM_FIRST_HARDFORK+1;
const Height UPGRADE_HEIGHT_V4                                         = INFINIUM_FIRST_HARDFORK+4;
const Height UPGRADE_HEIGHT_V5                                         = 25;                        //Developer fee
const Height KEY_IMAGE_SUBGROUP_CHECKING_HEIGHT                        = INFINIUM_FIRST_HARDFORK+2;
const Height INFINIUM_BLOCK_REWARD_LOWERING                            = INFINIUM_FIRST_HARDFORK+10;
const size_t DISABLE_VERSION_CHECK_FOR_CHECKPOINT                      = false; //enabled only becouse of impoting old chain, never use in normal situation 
const size_t ENABLE_CONNECTING_BETWEEN_SEED_NODES_WITH_STANDARD_CLIENT = true;

// Developer fee settings

const size_t ENABLE_DEVELOPER_FEE_DEBUGGING_STUFF = true;
const Amount DEVELOPER_FEE_PERCENTILE_PER_BLOCK   = 3; // 1.5% fee to developers it is not mandatory to pay it, but it is appreciated (it is 1.5% even if there is 3,
                                                       // becouse it is half, the fee is payed every other block to reduce stored data on the blockchain)
const std::string DEVELOPER_FEE_WALLET_ADDRESS    = "inf8VpqmHRoMiNqbck73gwdc9UjB42AKzhmESbpn9kBoBs7sPfmYj3YGJamMbPy3HQLYiQeshbMz3go9QxJeKETw1Md7qnpchq";

// Developer fee settings

// Radical simplification of consensus rules starts from versions
const uint8_t BLOCK_VERSION_AMETHYST       = 4;
const uint8_t TRANSACTION_VERSION_AMETHYST = 4;

const size_t MINIMUM_ANONYMITY_V1_3 = 0;
const size_t MINIMUM_ANONYMITY      = 3;

// Emission and formats
const Amount MONEY_SUPPLY            = std::numeric_limits<uint64_t>::max();
const unsigned EMISSION_SPEED_FACTOR = 18;
static_assert(EMISSION_SPEED_FACTOR <= 8 * sizeof(uint64_t), "Bad EMISSION_SPEED_FACTOR");

const size_t DISPLAY_DECIMAL_POINT    = 12;
const Amount MIN_DUST_THRESHOLD       = 1000000;            // Everything smaller will be split in groups of 3 digits
const Amount MAX_DUST_THRESHOLD       = 30000000000000000;  // Everything larger is dust because very few coins
const Amount SELF_DUST_THRESHOLD      = 1000;               // forfeit outputs smaller than this in a change
const Amount MAX_SUPPLY_RPC_DIVIDE_BY = 1000;               // divide already_generated_coins rpc response from get_block_header rpc command by this number

const uint64_t ADDRESS_BASE58_PREFIX          = 1288825;       // legacy addresses start with "inf8"
const uint64_t ADDRESS_BASE58_PREFIX_AMETHYST = 88386169;  // addresses start with "infi8"
const uint64_t SENDPROOF_BASE58_PREFIX =
    1174923897;  // proofs start with "infprf"
const char BLOCKS_FILENAME[]       = "blocks.bin";
const char BLOCKINDEXES_FILENAME[] = "blockindexes.bin";

// Difficulty and rewards
const Timestamp DIFFICULTY_TARGET              = 90;
const Height EXPECTED_NUMBER_OF_BLOCKS_PER_DAY = 24 * 60 * 60 / DIFFICULTY_TARGET;

const Difficulty MINIMUM_DIFFICULTY_V1 = 1;  // Genesis and some first blocks in main net
const Difficulty MINIMUM_DIFFICULTY    = 200;

const Height DIFFICULTY_WINDOW = 720;
const Height DIFFICULTY_CUT    = 60;  // out-of-family timestamps to cut after sorting
const Height DIFFICULTY_LAG    = 15;  // skip last blocks for difficulty calcs (against lowering difficulty attack)

const size_t is_for_debuging   = false; // don't care about this

static_assert(DIFFICULTY_WINDOW >= 2, "Bad DIFFICULTY_WINDOW");
static_assert(2 * DIFFICULTY_CUT <= DIFFICULTY_WINDOW - 2, "Bad DIFFICULTY_WINDOW or DIFFICULTY_CUT");

// Upgrade voting
const Height UPGRADE_VOTING_PERCENT = 90;
const Height UPGRADE_VOTING_WINDOW  = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY;
const Height UPGRADE_WINDOW         = EXPECTED_NUMBER_OF_BLOCKS_PER_DAY * 7;  // Delay after voting
static_assert(60 <= UPGRADE_VOTING_PERCENT && UPGRADE_VOTING_PERCENT <= 100, "Bad UPGRADE_VOTING_PERCENT");
static_assert(UPGRADE_VOTING_WINDOW > 1, "Bad UPGRADE_VOTING_WINDOW");

// Timestamps
const Timestamp BLOCK_FUTURE_TIME_LIMIT             = 60 * 60 * 2;
const Height BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW_V1_3 = 60;
const Height BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW      = 59;
static_assert(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW % 2 == 1,
    "This window must be uneven for median timestamp to grow monotonically");

// Locking by timestamp and by block
const Height MAX_BLOCK_NUMBER = 500000000;

// Legacy pre amethyst locking constants
const Height LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;
const int    SECOND_MINING_ALGO             = 3;

constexpr Timestamp LOCKED_TX_ALLOWED_DELTA_SECONDS(Timestamp difficulty_target) {
	return difficulty_target * LOCKED_TX_ALLOWED_DELTA_BLOCKS;
}

const Height MINED_MONEY_UNLOCK_WINDOW = 60;

// Size limits
const size_t MAX_HEADER_SIZE         = 2048;
const size_t BLOCK_CAPACITY_VOTE_MIN = 100 * 1000;   // min block size
const size_t BLOCK_CAPACITY_VOTE_MAX = 2000 * 1000;  // max block size
static_assert(BLOCK_CAPACITY_VOTE_MAX >= BLOCK_CAPACITY_VOTE_MIN, "Bad TRANSACTIONS_SIZE_VOTE");
const Height BLOCK_CAPACITY_VOTE_WINDOW = 11;

// Legacy pre amethyst size limits
const size_t MINIMUM_SIZE_MEDIAN_V3 = 75000;
const size_t MINIMUM_SIZE_MEDIAN_V2 = 60000;
const size_t MINIMUM_SIZE_MEDIAN_V1 = 40000;

const Height MEIDAN_BLOCK_SIZE_WINDOW       = 100;
/*const size_t MAX_BLOCK_SIZE_INITIAL         = 20 * 1024;   // block transactions size*/
const size_t MAX_BLOCK_SIZE_INITIAL         = 1000000000; //use inf value
const size_t MAX_BLOCK_SIZE_GROWTH_PER_YEAR = 100 * 1024;  // block transactions size

// P2p ports, not strictly part of consensus
const uint16_t P2P_DEFAULT_PORT        = 27854;
const uint16_t RPC_DEFAULT_PORT        = 27855;
const uint16_t WALLET_RPC_DEFAULT_PORT = 27856;

// We do not want runtime conversion, so compile-time converter
constexpr PublicKey P2P_STAT_TRUSTED_PUBLIC_KEY =
    common::pfh<PublicKey>("8f80f9a5a434a9f1510d13336228debfee9c918ce505efe225d8c94d045fa115");

constexpr PublicKey CHECKPOINT_PUBLIC_KEYS[] = {
    common::pfh<PublicKey>("b397e789ba603046d5750bbf490e1569f55dc9cf1f91edd2605d55d7bc3603fc"),
    common::pfh<PublicKey>("10fdd8f7331304b2818b86158be07e5e71441a3e96fccc3451f4c12862ce2d75"),
    common::pfh<PublicKey>("6e03debc66cfeabe0fb8720f4ed3a433a16a40dc9b72e6d14679f0b8a784cd58"),
    common::pfh<PublicKey>("7afcd21a758f0568d536bec2e613c8470c086c97f14dfec3f2a744492ad02f0f"),
    common::pfh<PublicKey>("64aadc345b4e12c10ae19e02a1536550abf0cb5118e9ad7d4c7184215a551240"),
    common::pfh<PublicKey>("247eb4681afe8fbbf09fa7145249be27f8afdaefb023850e1399aaf49747d5e4"),
    common::pfh<PublicKey>("eb39db3c11b09c637a06122e48d0ee88603e7b216dda01901daa27c485d82eff")};
constexpr PublicKey CHECKPOINT_PUBLIC_KEYS_TESTNET[] = {
    common::pfh<PublicKey>("577ac6a6cdc5e0114c5a7e6338f1332fd0684e2aaf7aa3efb415e9f623d04bf5"),
    common::pfh<PublicKey>("49950afc665e2f23354c03559f67e01e4f23fe2f30c6c6037b4de6dbd914ed80"),
    common::pfh<PublicKey>("07f8bba2577c0bfd9f5dc8af7319b6acbbde22bf95678927c707bb42e22fd157"),
    common::pfh<PublicKey>("9d385d34b2b4a4eb21cc1eab33ad0763b43423bdf9921db20ca5b13edd595b35"),
    common::pfh<PublicKey>("7b897d24abb76a31230b1de982be9b32a5f12dae716bbec4804a3866555e5cad"),
    common::pfh<PublicKey>("89ccf482916c8e381e344542537d908be76a0180e4043bf748407bd7b3b7193c"),
    common::pfh<PublicKey>("005d18764a7c4514d217d55f39633c8145e25afe91fd84837fc1a9ab5e048e8e")};
constexpr PublicKey CHECKPOINT_PUBLIC_KEYS_STAGENET[] = {
    common::pfh<PublicKey>("11bcb3340a24e7cc2d3e4faa4c4f66ff7ef2813c1ae49e4f8b545d14b0f79bdc"),
    common::pfh<PublicKey>("32be85c1afd74f924a7487a76dda12b4a9925adf6212c903d7188ebd16ce8495"),
    common::pfh<PublicKey>("d1789d5103bc8328285124dfc77d3fd3c5d3d76e70616bb409d84d3f335326cf"),
    common::pfh<PublicKey>("8ccd5e4828b4b3d785e0f9c910771271ad40e9b1f427db1df9021a7a4083288c"),
    common::pfh<PublicKey>("6269b60e38cd1879807e3591f1e19b936c4d156a3d15b0693a8700ee7770e431"),
    common::pfh<PublicKey>("c9b8aa2f09fb81f77c135d1eb23cd7eac5b66c409058d5b53f724a1b887fe70f"),
    common::pfh<PublicKey>("62020c71bbf2447ee588b28c15430434f2ceac8443c40b6e48b627e437110981")};

const char *const SEED_NODES[] = {
    "45.80.150.33:27854", "135.181.62.60:27854", "8.210.48.142:27854", "144.217.29.34:27854"};
const char *const SEED_NODES_STAGENET[] = {
    "207.246.127.160:10080", "108.61.174.232:10080", "45.32.156.183:10080", "45.76.29.96:10080"};
// testnet will have no seed nodes

constexpr const HardCheckpoint CHECKPOINTS[] = {
    //{1, common::pfh<Hash>("1a3599e86f1f42132eedfc4a8ef94f0d3f4e2a081b2d624dc2bf3abb7e3f691d")},
    //{10, common::pfh<Hash>("1c3478922aa905eb40dd93fb0b3c06a93b47bfab4a901ffcbab51e57ff2aa0e1")},
   // {100, common::pfh<Hash>("1e96b8c578c7ce0e28928449d3cafd1dbdecfa38ab0058e5965a9a464098eaf1")},
    //{1000, common::pfh<Hash>("10cd7cefda15c4eee76710899dbafae79c9316dd36322a9cd48ddb227db4c215")},
   // {10000, common::pfh<Hash>("49e28456d2db6d771c9386feed8b5f66e77a40a1edc10bce27ae27b3fe959311")},
    {50000, common::pfh<Hash>("7d44bcf52ea88bf50719ce03517f61d9352986316f39ba2d1e0bbc49d4b02061")},
    {75000, common::pfh<Hash>("1bad180af3e9fcbe6889ba14fbbeb8351a35e8c2993ea098cd17cb802ee59e09")},
    {150000, common::pfh<Hash>("69234bfdc23773aed0d2c135dd875535e3d1e54b11a074ce9b702320216155e0")},
    {300000, common::pfh<Hash>("c623b089a5ee606510e61a716fcfcda89575220d58c90e9015006b359db5743c")},
    {450000, common::pfh<Hash>("a050cbb6034ae801a28d24753ac6f9d72fd7eef2b99609c9ed98a7095609f50f")},
    {600000, common::pfh<Hash>("1931b95fe69a6cbd6dfc100945f336aaa6af094e579cec380bce41f42a80b032")},
    {750000, common::pfh<Hash>("15599ae78bf4f5adec0a29b73e0cd8927b62250c5ab7b6090b1a1343e951f3ea")},
    {900000, common::pfh<Hash>("3f0b119b3545227f3866193786fa532376b1b6aa8ef81cd56bd0d96fec6e6159")},
    {1000000, common::pfh<Hash>("1f8176e590abf4fbec517e1722b3dda86589527d44e48a6fa7d6b15437c4d2e7")},
    {1000666, common::pfh<Hash>("f31d2bc0775a2be82d0055c97c26ccb562f2e5d641f519d61df15b3e7440e80d")},
    {1050000, common::pfh<Hash>("c50e434538a419ab36836179e985ba4f1f3869a8cfb1a91d5a4052dc72b4332a")},
    {1200000, common::pfh<Hash>("a1293f095e45e95732a0e1bcc7de1cc056be15c69ede25ebb20d319f0c615328")},
    {1350000, common::pfh<Hash>("9ae6bda945434fd770085077ac9f2778f7d73b4c5b2934d4c68b664373a9263e")},
    {1500000, common::pfh<Hash>("ca44120df6deb420004aa29f9be3f431049328598c9f0df190a31f405989efbf")},
    {1650000, common::pfh<Hash>("bf9eaace801cebb12557661711bdf97349c168dde3c5a289d82dc4a24e7ea1e3")},
    {1800000, common::pfh<Hash>("ece8dd77ce20dcb309b711cb64681477be0accbb5a89ffc048886448901c7cc4")},
    {1950000, common::pfh<Hash>("80c95eb9deab2ac17537ee2cf286070907bf238d61678a11aef4e20265463419")},
    {1990000, common::pfh<Hash>("8077438850060cc1e5aa30d3dba29fb352cfdf4a29a84abc080789cda0faeb61")},
    {2000000, common::pfh<Hash>("e38a98081d934c3c5ab5c8dff477a1244a250d0cfd04411d5540a8435dc1af5f")},
    {2030000, common::pfh<Hash>("6b86e80df9d8fedd58ab62aaec141f96026e49f6d5d38ac094382897feefed44")},
    {2060000, common::pfh<Hash>("c0d0c138dee02a331fd539387370aa01c19c2c9053772e961eaac38cf1826442")},
    {2065600, common::pfh<Hash>("30fd707ba340bd75fd4a8e6c2cc44b5067943b7fbb584c6af476fadd6cca17f7")},
    {2065601, common::pfh<Hash>("18a58cbd8249571dbaa2e97f97eb902628f2004b60d8acda1d491838d9da5f06")},
    {2065602, common::pfh<Hash>("194a895f380eb9a54f108115d6d65dd0765aa29288c624137e743368aceed782")},
    {2065604, common::pfh<Hash>("107d76c53671f9d1d02fa3a2c9837a84aff524a1959bc9108176913c1c96a0db")},
    {2065610, common::pfh<Hash>("94ab42d3c9c265c1e5923a31d667db02b36a18eb5f2310a58463c1814e7904e5")},
    {2065611, common::pfh<Hash>("c06f9f64d9b86ae6283ee747f9a49921235a1a144cbc42c5794d2128a1730546")},
    {2066800, common::pfh<Hash>("fe88ab36c46acf42cb24ad602b0dc3476cc2fb30390f9cbea751235b5991bc9e")},
    {2066804, common::pfh<Hash>("0b7ac9b50c9413c2bc0e69fd67077436054a6481525a636b758456aa83c73878")},
    {2070700, common::pfh<Hash>("b645cd0e7f320c0552c5d0dfd7c670b39366616769d69ac580201156eda42d68")}};

// When adding checkpoint and BEFORE release, you MUST check that daemon fully syncs both mainnet and stagenet.

// Be extra careful when setting checkpoint around consensus update heights. Follow rules:
// 1. never set checkpoint after or to height where required # of votes for upgrade was gathered
// 2. never set checkpoint before height where upgrade happened (with desired major version)
// 3. after setting checkpoint after upgrade, modify upgrade_heights array

constexpr const HardCheckpoint CHECKPOINTS_STAGENET[] = {
    {450, common::pfh<Hash>("c69823a6b3e0c1f724411e697219a9d31a2df900cb49bb0488b1a91a9989a805")},
    {30000, common::pfh<Hash>("4a3b02206d120bab6c3bef4a7bcbc1934b5327c27c181d790f4db407dc92c640")},
    {49000, common::pfh<Hash>("1960a677cda6afd47dd4a928bf876b7cb7c9bd86107e3193ca9b0fd0926bad4c")},
    {70000, common::pfh<Hash>("10ce87ab253c1142414a700336795057781572b5d9f026c57463ae420e456240")}};
}}  // namespace cn::parameters