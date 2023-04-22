#pragma once

#include "util_cout.h"
#include "util_string.h"
#include "OpenFHE_setting.h"
#include "proto_setting.h"

// parse the protobuf message to FHE parameters
void Message2FHEParameters(const Root& msg, CCParams<CryptoContextBGVRNS>& parameters, 
        CryptoContext<DCRTPoly>& context, KeyPair<DCRTPoly>& keyPair){
    auto param = msg.param();
    
    if(param.has_multiplicativedepth())
        parameters.SetMultiplicativeDepth(param.multiplicativedepth());
    parameters.SetPlaintextModulus(param.plaintextmodulus());
    // TEST: use default value
    // if(param.has_scaltech())
    //     parameters.SetScalingTechnique((ScalingTechnique)param.scaltech());
    if(param.has_batchsize())
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
        
    parameters.SetNoiseEstimate(param.noiseestimate());
    parameters.SetDesiredPrecision(param.desiredprecision());
    if(param.has_statisticalsecurity())
        parameters.SetStatisticalSecurity(param.statisticalsecurity());
    if(param.has_numadversarialqueries())
        parameters.SetNumAdversarialQueries(param.numadversarialqueries());

    cout<<parameters<<endl;
    // generate context
    context = GenCryptoContext(parameters);
    context->Enable(PKE);
    context->Enable(KEYSWITCH);       
    context->Enable(LEVELEDSHE);
    context->Enable(ADVANCEDSHE);
    if(param.pre())
        context->Enable(PRE);
    if(param.multiparty())
        context->Enable(MULTIPARTY);
    if(param.fhe())
        context->Enable(FHE);
    keyPair = context->KeyGen();
    context->EvalMultKeyGen(keyPair.secretKey);
    vector<int> rotateIndexes(param.rotateindexes().begin(), param.rotateindexes().end());
    // cout << "rotateIndexes: " << rotateIndexes << endl;
    if(rotateIndexes.size() > 0)
        context->EvalRotateKeyGen(keyPair.secretKey, rotateIndexes);
}