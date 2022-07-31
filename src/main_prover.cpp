#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <gmp.h>
#include <memory>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <alt_bn128.hpp>
#include "binfile_utils.hpp"
#include "zkey_utils.hpp"
#include "wtns_utils.hpp"
#include "groth16.hpp"

using json = nlohmann::json;

#define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

std::vector<uint8_t> get(const size_t min, const size_t max, const uint64_t id, const uint8_t* data, size_t idx = 0) {
    (void)id;

    size_t left(sizeof(data));

    uint32_t getSize;
    if ( left < sizeof(getSize) ) {
        throw;
    }
    memcpy(&getSize, data + idx, sizeof(getSize));
    idx += sizeof(getSize);
    left -= sizeof(getSize);

    if ( getSize < min ) {
        getSize = min;
    }
    if ( max && getSize > max ) {
        getSize = max;
    }

    if ( left < getSize ) {
        throw;
    }

    std::vector<uint8_t> ret(getSize);

    if ( getSize > 0 ) {
        memcpy(ret.data(), data + idx, getSize);
    }
    idx += getSize;
    left -= getSize;

    return ret;
}

template<class T> T Get(const uint8_t* data, const uint64_t id = 0)
{
    T ret;
    const auto v = get(sizeof(ret), sizeof(ret), id, data, 0);
    memcpy(&ret, v.data(), sizeof(ret));
    return ret;
}

int main(int argc, char **argv) {

    /*
    if (argc != 5) {
        std::cerr << "Invalid number of parameters:\n";
        std::cerr << "Usage: prove <circuit.zkey> <witness.wtns> <proof.json> <public.json>\n";
        return -1;
    }
    */

    uint64_t fuzz_in = strtoull(argv[1], NULL, 0);

    mpz_t altBbn128r;

    mpz_init(altBbn128r);
    mpz_set_str(altBbn128r, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

    try {
        /*
        std::string zkeyFilename = argv[1];
        std::string wtnsFilename = argv[2];
        std::string proofFilename = argv[3];
        std::string publicFilename = argv[4];
        */

        ZKeyUtils::Header* zkeyHeader = new ZKeyUtils::Header();
        // Use fixed parameters for the bn128 curve. In a future iteration, should also set this from input given by the fuzzer
        zkeyHeader->n8q = 32;
        mpz_init_set_str(zkeyHeader->qPrime, "21888242871839275222246405745257275088696311157297823662689037894645226208583", 10);
        zkeyHeader->n8r = 32;
        mpz_init_set_str(zkeyHeader->rPrime, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);

        // Use input from fuzzer to define the rest of the zkey header
        zkeyHeader->nVars = Get<u_int32_t>(0, fuzz_in);
        zkeyHeader->nPublic = Get<u_int32_t>(0, fuzz_in);
        zkeyHeader->domainSize = Get<u_int32_t>(0, fuzz_in);
        zkeyHeader->nCoefs = Get<u_int64_t>(0, fuzz_in);

        vector<u_int64_t> tmp;
        for(int i=0; i<3; i ++) {
            tmp.push_back(Get<u_int64_t>(0, fuzz_in));
        }

        vector<u_int64_t> tmp2; 
        for(int i=0; i<3; i++){
            vector<u_int64_t> tmp3;
            for(int j=0; j<2; j++) {
                tmp3.push_back(Get<u_int64_t>(0, fuzz_in));
            }
            tmp2.insert(tmp2.end(), tmp3.begin(), tmp3.end());
        }

        zkeyHeader->vk_alpha1 = &tmp;
        zkeyHeader->vk_beta1 = &tmp;
        zkeyHeader->vk_beta2 = &tmp2;
        zkeyHeader->vk_gamma2 = &tmp2;
        zkeyHeader->vk_delta1 = &tmp;
        zkeyHeader->vk_delta2 = &tmp2;

        /*
        auto zkey = BinFileUtils::openExisting(zkeyFilename, "zkey", 1);
        auto zkeyHeader = ZKeyUtils::loadHeader(zkey.get());

        std::string proofStr;
        if (mpz_cmp(zkeyHeader->rPrime, altBbn128r) != 0) {
            throw std::invalid_argument( "zkey curve not supported" );
        }

        auto wtns = BinFileUtils::openExisting(wtnsFilename, "wtns", 2);
        auto wtnsHeader = WtnsUtils::loadHeader(wtns.get());

        if (mpz_cmp(wtnsHeader->prime, altBbn128r) != 0) {
            throw std::invalid_argument( "different wtns curve" );
        }
        */
        u_int64_t fuzz_val = Get<u_int64_t>(0, fuzz_in);
        auto prover = Groth16::makeProver<AltBn128::Engine>(
            zkeyHeader->nVars,
            zkeyHeader->nPublic,
            zkeyHeader->domainSize,
            zkeyHeader->nCoefs,
            zkeyHeader->vk_alpha1,
            zkeyHeader->vk_beta1,
            zkeyHeader->vk_beta2,
            zkeyHeader->vk_delta1,
            zkeyHeader->vk_delta2,
            &fuzz_val,    // Coefs
            &fuzz_val,    // pointsA
            &fuzz_val,    // pointsB1
            &fuzz_val,    // pointsB2
            &fuzz_val,    // pointsC
            &fuzz_val     // pointsH1
        );
        string fuzz_val_str = Get<string>(0, fuzz_in);
        RawFr* wtnsTmp = new RawFr();
        RawFr::Element element;
        //wtnsTmp->FqRawElement = fuzz_val;
        wtnsTmp->fromString(element, fuzz_val_str);
        AltBn128::FrElement *wtnsData = &element;
        auto proof = prover->prove(wtnsData);

        /*
        std::ofstream proofFile;
        proofFile.open (proofFilename);
        proofFile << proof->toJson();
        proofFile.close();

        std::ofstream publicFile;
        publicFile.open (publicFilename);

        json jsonPublic;
        AltBn128::FrElement aux;
        for (int i=1; i<=zkeyHeader->nPublic; i++) {
            AltBn128::Fr.toMontgomery(aux, wtnsData[i]);
            jsonPublic.push_back(AltBn128::Fr.toString(aux));
        }

        publicFile << jsonPublic;
        publicFile.close();
        */
    } catch (std::exception& e) {
        mpz_clear(altBbn128r);
        std::cerr << e.what() << '\n';
        return -1;
    }

    mpz_clear(altBbn128r);
    
    exit(EXIT_SUCCESS);
}
