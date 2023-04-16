#ifndef OPENFHE_CKKS_PARSER_H
#define OPENFHE_CKKS_PARSER_H

#include "util_cout.h"
#include "util_string.h"
#include "OpenFHE_setting.h"
#include "/root/Refine_Protobuf_Mutator/proto/proto_setting.h"

// parse the protobuf message to FHE parameters
void Message2FHEParameters(const Root& msg, CCParams<CryptoContextCKKSRNS>& parameters, 
        CryptoContext<DCRTPoly>& context, KeyPair<DCRTPoly>& keyPair){
    auto param = msg.param();
    if(param.has_multiplicativedepth())
            parameters.SetMultiplicativeDepth(param.multiplicativedepth());
    parameters.SetPlaintextModulus(param.plaintextmodulus());
    parameters.SetBatchSize(param.batchsize());
    parameters.SetDigitSize(param.digitsize());
    if(param.has_standarddeviation())
        parameters.SetStandardDeviation(param.standarddeviation());
    if(param.has_secretkeydist())
        parameters.SetSecretKeyDist((SecretKeyDist)param.secretkeydist());
    if(param.has_maxrelinskdeg())
        parameters.SetMaxRelinSkDeg(param.maxrelinskdeg());
    if(param.has_kstech())
        parameters.SetKeySwitchTechnique((KeySwitchTechnique)param.kstech());
    if(param.has_scaltech())
        parameters.SetScalingTechnique((ScalingTechnique)param.scaltech());
    if(param.has_firstmodsize())
        parameters.SetFirstModSize(param.firstmodsize());
    parameters.SetScalingModSize(param.scalingmodsize());
    parameters.SetNumLargeDigits(param.numlargedigits());
    parameters.SetSecurityLevel((SecurityLevel)param.securitylevel());
    parameters.SetRingDim(param.ringdim());
    parameters.SetEvalAddCount(param.evaladdcount());
    parameters.SetKeySwitchCount(param.keyswitchcount());
    parameters.SetEncryptionTechnique((EncryptionTechnique)param.encryptiontechnique());
    if(param.has_multiplicationtechnique())
        parameters.SetMultiplicationTechnique((MultiplicationTechnique)param.multiplicationtechnique());
    parameters.SetMultiHopModSize(param.multihopmodsize());
    if(param.has_premode())
        parameters.SetPREMode((ProxyReEncryptionMode)param.premode());
    if(param.has_multipartymode())
        parameters.SetMultipartyMode((MultipartyMode)param.multipartymode());
    parameters.SetExecutionMode((ExecutionMode)param.executionmode());
    parameters.SetDecryptionNoiseMode((DecryptionNoiseMode)param.decryptionnoisemode());
    parameters.SetNoiseEstimate(param.noiseestimate());
    if(param.has_desiredprecision())
        parameters.SetDesiredPrecision(param.desiredprecision());
    if(param.has_statisticalsecurity())
        parameters.SetStatisticalSecurity(param.statisticalsecurity());
    if(param.has_numadversarialqueries())
        parameters.SetNumAdversarialQueries(param.numadversarialqueries());

    // generate context
    context = GenCryptoContext(parameters);
    if(param.pke())
        context->Enable(PKE);
    if(param.keyswitch())
        context->Enable(KEYSWITCH);       
    if(param.pre())
        context->Enable(PRE);
    if(param.leveledshe())
        context->Enable(LEVELEDSHE);
    if(param.advancedshe())
        context->Enable(ADVANCEDSHE);
    if(param.multiparty())
        context->Enable(MULTIPARTY);
    keyPair = context->KeyGen();
    context->EvalMultKeyGen(keyPair.secretKey);
    if(param.fhe())
        context->Enable(FHE);
    vector<int> shiftIndexes;
    std::set<int>s;
    for(auto api : msg.apisequence().apilist()){
        if(api.has_shiftonelist()) {
            int index = api.shiftonelist().index();
            s.insert(index);
        }
    }
    for(auto it : s) shiftIndexes.push_back(it);
    if(shiftIndexes.size() > 0)
        context->EvalRotateKeyGen(keyPair.secretKey, shiftIndexes);
}

#endif