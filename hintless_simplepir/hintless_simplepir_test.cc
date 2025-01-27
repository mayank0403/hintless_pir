// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <memory>
#include <string>
#include <map>

using namespace std;

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hintless_simplepir/client.h"
#include "hintless_simplepir/database_hwy.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/server.h"
#include "hintless_simplepir/utils.h"
#include "linpir/parameters.h"
#include "shell_encryption/testing/status_testing.h"

namespace hintless_pir {
namespace hintless_simplepir {
namespace {

using RlweInteger = Parameters::RlweInteger;

const Parameters kParameters{
    .db_rows = 1024,
    .db_cols = 1024,
    .db_record_bit_size = 8,
    .lwe_secret_dim = 1408,
    .lwe_modulus_bit_size = 32,
    .lwe_plaintext_bit_size = 8,
    .lwe_error_variance = 8,
    .linpir_params =
        linpir::RlweParameters<RlweInteger>{
            .log_n = 12,
            .qs = {35184371884033ULL, 35184371703809ULL},  // 90 bits
            .ts = {2056193, 1990657},                      // 42 bits
            .gadget_log_bs = {16, 16},
            .error_variance = 8,
            .prng_type = rlwe::PRNG_TYPE_HKDF,
            .rows_per_block = 1024,
        },
    .prng_type = rlwe::PRNG_TYPE_HKDF,
};

// All recorded metrics
#define HINT_MB "Hints (MiB)"
#define ONLINE_STATE_KB "Online State (KiB)"
#define PREPARE_UP_KB "Prep Up (Kib)"
#define PREPARE_DOWN_KB "Prep Down (KiB)"
#define QUERY_UP_KB "Query Up (KiB)"
#define QUERY_DOWN_KB "Query Down (KiB)"
#define GLOBAL_PREPR_S "Global Prepr (S)"
#define CLIENT_PREP_PRE_S "Client Prepa Pre Req (s)"
#define SERVER_PREP_S "Server Prepa Comp (s)"
#define CLIENT_PREP_POST_S "Client Prepa Post Req (s)"
#define CLIENT_Q_REQ_GEN_MS "Query: Client Req Gen (ms)"
#define SERVER_Q_RESP_S "Query: Server Comp (s)"
#define CLIENT_Q_DEC_MS "Query: Client Decryption (ms)"
#define DIRECT_CLIENT_Q_MS "Direct ~ Client Query Gen (ms)" // Direct means without prepare. Directly running full online phase as conventionally done
#define DIRECT_SERVER_Q_S "Direct ~ Server Response (s)"
#define DIRECT_CLIENT_REC_MS "Direct ~ Client Record Rec (ms)"
#define DIRECT_UP_KB "Direct ~ Up (KiB)"
#define DIRECT_DOWN_KB "Direct ~ Down (KiB)"

TEST(HintlessSimplePir, EndToEndTest) {

  // Important metrics
  std::map<string, double> dict;
  dict[HINT_MB] = 0; // mb is MiB, kb is KiB, s is sec, ms is ms
  dict[ONLINE_STATE_KB] = 0;
  dict[PREPARE_UP_KB] = 0;
  dict[PREPARE_DOWN_KB] = 0;
  dict[QUERY_UP_KB] = 0;
  dict[QUERY_DOWN_KB] = 0;
  dict[GLOBAL_PREPR_S] = 0;
  dict[CLIENT_PREP_PRE_S] = 0;
  dict[SERVER_PREP_S] = 0;
  dict[CLIENT_PREP_POST_S] = 0;
  dict[CLIENT_Q_REQ_GEN_MS] = 0;
  dict[SERVER_Q_RESP_S] = 0;
  dict[CLIENT_Q_DEC_MS] = 0;
  dict[DIRECT_CLIENT_Q_MS] = 0;
  dict[DIRECT_SERVER_Q_S] = 0;
  dict[DIRECT_CLIENT_REC_MS] = 0;
  dict[DIRECT_UP_KB] = 0;
  dict[DIRECT_DOWN_KB] = 0;

#ifdef FAKE_RUN
  std::cout << "\n          ----->>    Fake Run   <<-----           \n" << std::endl;
#endif
  double start, end;
  // Create server and fill in random database records.
  ASSERT_OK_AND_ASSIGN(auto server,
                       Server::CreateWithRandomDatabaseRecords(kParameters));

  // Preprocess the server and get public parameters.
  start = currentDateTime();
  ASSERT_OK(server->Preprocess());
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Server preprocessing time: " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[GLOBAL_PREPR_S] += (end-start)/1000;
  auto public_params = server->GetPublicParams();

  const Database* database = server->GetDatabase();
  auto H_vec = database->Hints();
  int shards = database->NumShards();
  uint64_t hint_bytes = shards * H_vec[0].size() * H_vec[0][0].size() * sizeof(hintless_pir::lwe::Integer);
  dict[HINT_MB] += hint_bytes / (1ULL << 20);

  // Create a client and issue request.
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Client creation time: " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;

  // Prepare phase
  double start_prepare, end_prepare;
  start_prepare = currentDateTime();
  
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto As_s_tuple, client->Compute_A_times_s());
  end = currentDateTime();
  //std::cout << "[==> TIMER  <==] Client A*s generation time: " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[CLIENT_PREP_PRE_S] += (end-start)/1000;
  
  auto As = std::get<0>(As_s_tuple);
  auto s_lwe = std::get<1>(As_s_tuple);
  dict[ONLINE_STATE_KB] += (As.size() * sizeof(hintless_pir::lwe::Integer))/(1ULL << 10);
  dict[ONLINE_STATE_KB] += (s_lwe.Key().size() * sizeof(hintless_pir::lwe::Integer))/(1ULL << 10);

  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto prepare_req, client->PrepareLinPirGivenS(s_lwe));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Client prepare req gen time: " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[CLIENT_PREP_PRE_S] += (end-start)/1000;
  
  std::cout << "[==> COMM. <==] Client prepare request KB " << (prepare_req.ByteSizeLong() / 1024) << std::endl;
  dict[PREPARE_UP_KB] += (prepare_req.ByteSizeLong() / 1024);
  std::cout << "[ONLINE PREPARE STATE]: Client prepare request (rotation keys, RLWE cipher of s_lwe) size " << (prepare_req.ByteSizeLong() / 1024) << " KB" << std::endl;
  dict[ONLINE_STATE_KB] += (prepare_req.ByteSizeLong() / 1024);

  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto prepare_response, server->HandlePrepareRequest(prepare_req));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Server prepare response time (LinPir H*s compute time): " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[SERVER_PREP_S] += (end-start)/1000;

  std::cout << "[==> COMM. <==] Server prepare response KB " << (prepare_response.ByteSizeLong() / 1024) << std::endl;
  dict[PREPARE_DOWN_KB] += (prepare_response.ByteSizeLong() / 1024);
  std::cout << "[ONLINE PREPARE STATE]: Client prepare response from server (Hs) size " << (prepare_response.ByteSizeLong() / 1024) << " KB" << std::endl;
  dict[ONLINE_STATE_KB] += (prepare_response.ByteSizeLong() / 1024);

  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto hs_vec, client->RecoverHsPreparePhase(prepare_response));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Client prepare recover time (LinPir response decryption): " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[CLIENT_PREP_POST_S] += (end-start)/1000;
  std::cout << "[ONLINE STATE]: Size of decrypted H*s (i.e. w) " << (hs_vec.size() * hs_vec[0].size() * sizeof(hintless_pir::lwe::Integer))/(1ULL << 10) << " KB" << std::endl;
  dict[ONLINE_STATE_KB] += (hs_vec.size() * hs_vec[0].size() * sizeof(hintless_pir::lwe::Integer))/(1ULL << 10);

  end_prepare = currentDateTime();
  std::cout << "[==> TIMER  <==] Prepare phase total (client + server) time: " << (end_prepare-start_prepare) << " ms | " << (end_prepare-start_prepare)/1000 << " sec" << std::endl;
  std::cout << "----------------------------------" << std::endl;
  
  double start_online, end_online;
  start_online = currentDateTime();

  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto request_and_query, client->GenerateRequestGivenAsSkipLinPir(1, As, s_lwe));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Client online request generation time (skipped LinPir): " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[CLIENT_Q_REQ_GEN_MS] += (end-start);
	
  auto request = request_and_query.first;
	auto query = request_and_query.second;

  std::cout << "[==> COMM. <==] Client online request (LWE only) KB " << (request.ByteSizeLong() / 1024) << std::endl;
  dict[QUERY_UP_KB] += (request.ByteSizeLong() / 1024);
  std::cout << "[ONLINE STATE]: Client request (LWE query only) size " << (request.ByteSizeLong() / 1024) << " KB" << std::endl;
  dict[ONLINE_STATE_KB] += (request.ByteSizeLong() / 1024);

	// Server handles the HintlessPIR request
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto response, server->HandleRequestSkipLinPir(request)); 
  std::cout << "Request handled" << std::endl;
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Server-only Online time (only D*u): " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[SERVER_Q_RESP_S] += (end-start)/1000;

  std::cout << "[==> COMM. <==] Server response (skipped LinPir) KB " << (response.ByteSizeLong() / 1024) << std::endl;
  dict[QUERY_DOWN_KB] += (response.ByteSizeLong() / 1024);
  std::cout << "[ONLINE STATE]: Client response from server (Du) size " << (response.ByteSizeLong() / 1024) << " KB" << std::endl;
  dict[ONLINE_STATE_KB] += (response.ByteSizeLong() / 1024);

  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto record, client->RecoverRecordGivenHs(response, hs_vec));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Client record recovery time (given Hs already): " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[CLIENT_Q_DEC_MS] += (end-start);

  end_online = currentDateTime();
  std::cout << "[==> TIMER  <==] Online-only (w/o prepare) phase total (client + server) time: " << (end_online-start_online) << " ms | " << (end_online-start_online)/1000 << " sec" << std::endl;

  ASSERT_OK_AND_ASSIGN(auto expected, database->Record(1));
  EXPECT_EQ(record, expected);

  //Without prepare phase
  std::cout << "-------- Running online phase directly as well ---------" << std::endl;
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto request_dir, client->GenerateRequest(1));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Client request generation time: " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[DIRECT_CLIENT_Q_MS] += (end-start);

  std::cout << "[==> COMM. <==] Client request KB " << (request_dir.ByteSizeLong() / 1024) << std::endl;
  dict[DIRECT_UP_KB] += (request_dir.ByteSizeLong() / 1024);
  
  // Handle the request
  
  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto response_dir, server->HandleRequest(request_dir));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Server-only online time: " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[DIRECT_SERVER_Q_S] += (end-start)/1000;

  std::cout << "[==> COMM. <==] Server response KB " << (response_dir.ByteSizeLong() / 1024) << std::endl;
  dict[DIRECT_DOWN_KB] += (response_dir.ByteSizeLong() / 1024);

  start = currentDateTime();
  ASSERT_OK_AND_ASSIGN(auto record_direct, client->RecoverRecord(response_dir));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Client record recovery time: " << (end-start) << " ms | " << (end-start)/1000 << " sec" << std::endl;
  dict[DIRECT_CLIENT_REC_MS] += (end-start);

  EXPECT_EQ(record_direct, expected);

  std::cout << "-----------------------------" << std::endl;
  for (auto it : dict) {
    std::cout << it.first << " : " << it.second << std::endl;
  }
}

/*
TEST(HintlessSimplePir, EndToEndTestWithChaChaPrng) {
  // Use ChaCha PRNG in both LinPIR and SimplePIR sub-protocols.
  Parameters params = kParameters;
  params.linpir_params.prng_type = rlwe::PRNG_TYPE_CHACHA;
  params.prng_type = rlwe::PRNG_TYPE_CHACHA;

  // Create server and fill in random database records.
  ASSERT_OK_AND_ASSIGN(auto server,
                       Server::CreateWithRandomDatabaseRecords(params));

  // Preprocess the server and get public parameters.
  ASSERT_OK(server->Preprocess());
  auto public_params = server->GetPublicParams();

  // Create a client and issue request.
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(params, public_params));
  ASSERT_OK_AND_ASSIGN(auto request, client->GenerateRequest(1));

  double start, end;
  start = currentDateTime();
  // Handle the request
  ASSERT_OK_AND_ASSIGN(auto response, server->HandleRequest(request));
  end = currentDateTime();
  std::cout << "[==> TIMER  <==] Server-only online time: " << (end-start) << " ms" << std::endl;
  ASSERT_OK_AND_ASSIGN(auto record, client->RecoverRecord(response));

  const Database* database = server->GetDatabase();
  ASSERT_OK_AND_ASSIGN(auto expected, database->Record(1));
  EXPECT_EQ(record, expected);
}
*/

}  // namespace
}  // namespace hintless_simplepir
}  // namespace hintless_pir
