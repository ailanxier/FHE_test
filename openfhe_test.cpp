#include "openfhe_test.h"

int main(int argc, char **argv){
    // clear_all_data();
    CryptoContext<DCRTPoly> client_context, server_context;
    std::fstream info_fstream(info_fileName, std::ios::trunc | std::ios::in | std::ios::out | std::ios::binary);
    std::fstream result_fstream(result_filename, std::ios::trunc | std::ios::in | std::ios::out | std::ios::binary);
    Print("---------------------OpenFHE---------------------");
    // ԭʼ����
try{
    client_init_context(argv[1], client_context, info_fstream);
    client_encrypt_data(client_context, info_fstream);
    server_init_context(server_context, info_fstream, result_fstream);

    // rescale after multiplication in FIXEDMANUAL mode
    #define isRescaleManual (std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(server_context->GetCryptoParameters())->GetScalingTechnique() == FIXEDMANUAL)
    for(auto api : msg.apisequence().apilist()){
        int dst = api.dst();
        if(api.has_addtwolist()){
            int src1 = api.addtwolist().src1();
            int src2 = api.addtwolist().src2();
            Print_words({"addtwo src1:", ToStr(src1), ", src2: ", ToStr(src2), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_add(data[src1], data[src2], data[dst]);
            server_ctxts[dst] = server_context->EvalAdd(server_ctxts[src1], server_ctxts[src2]);
        }else if(api.has_addconstant()){
            int src = api.addconstant().src();
            double num = api.addconstant().num();
            Print_words({"addconstant src:", ToStr(src), ", num: ", ToStr(num), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_add(data[src], num, data[dst]);
            server_ctxts[dst] = server_context->EvalAdd(server_ctxts[src], num);
        }else if(api.has_addmanylist()){
            vector<Ciphertext<DCRTPoly>> temp_many_ctxts;
            vector<dataType> temp(dataLen, 0);
            Print("addmany src:", 1, NO_STAR_LINE);
            for(auto& src : api.addmanylist().srcs()){
                temp_many_ctxts.push_back(server_ctxts[src]);
                vector_add(temp, data[src], temp);
                Printf("%d ", src);
            }
            data[dst].assign(temp.begin(), temp.end());
            Printf("dst: %d\n", dst);
            server_ctxts[dst] = server_context->EvalAddMany(temp_many_ctxts);
        }else if(api.has_subtwolist()){
            int src1 = api.subtwolist().src1();
            int src2 = api.subtwolist().src2();
            Print_words({"subtwo src1:", ToStr(src1), ", src2: ", ToStr(src2), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_sub(data[src1], data[src2], data[dst]);
            server_ctxts[dst] = server_context->EvalSub(server_ctxts[src1], server_ctxts[src2]);
        }else if(api.has_subconstant()){
            int src = api.subconstant().src();
            double num = api.subconstant().num();
            Print_words({"subconstant src:", ToStr(src), ", num: ", ToStr(num), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_sub(data[src], num, data[dst]);
            server_ctxts[dst] = server_context->EvalSub(server_ctxts[src], num);
        }else if(api.has_multwolist()){
            int src1 = api.multwolist().src1();
            int src2 = api.multwolist().src2();
            Print_words({"multwo src1:", ToStr(src1), ", src2: ", ToStr(src2), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_mul(data[src1], data[src2], data[dst]);
            server_ctxts[dst] = server_context->EvalMult(server_ctxts[src1], server_ctxts[src2]);
        }else if(api.has_mulconstant()){
            int src = api.mulconstant().src();
            double num = api.mulconstant().num();
            Print_words({"mulconstant src:", ToStr(src), ", num: ", ToStr(num), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_mul(data[src], num, data[dst]);
            server_ctxts[dst] = server_context->EvalMult(server_ctxts[src], num);
        }else if(api.has_mulmanylist()){
            vector<Ciphertext<DCRTPoly>> temp_many_ctxts;
            vector<dataType> temp(dataLen, 1);
            Print("mulmany src:", 1, NO_STAR_LINE);
            for(auto& src : api.mulmanylist().srcs()){
                temp_many_ctxts.push_back(server_ctxts[src]);
                vector_mul(temp, data[src], temp);
                Printf("%d ", src);
            }
            Printf("dst: %d\n", dst);
            data[dst].assign(temp.begin(), temp.end());
            server_ctxts[dst] = server_context->EvalMultMany(temp_many_ctxts);
        }else if(api.has_linearweightedsum()){
            vector<ConstCiphertext<DCRTPoly>> temp_many_ctxts;
            vector<dataType> res(dataLen, 0), mul_temp(dataLen, 0);
            vector<double> weights(api.linearweightedsum().weights().begin(), api.linearweightedsum().weights().end());
            Print("linearweightedsum src:", 1, NO_STAR_LINE);
            int i = 0;
            for(auto& src : api.linearweightedsum().srcs()){
                temp_many_ctxts.push_back(server_ctxts[src]);
                vector_mul(data[src], weights[i++], mul_temp);
                vector_add(res, mul_temp, res);
                Printf("%d ", src);
            }
            Printf("dst: %d\n", dst);
            data[dst].assign(res.begin(), res.end());
            server_ctxts[dst] = server_context->EvalLinearWSum(temp_many_ctxts, weights);
        }else if(api.has_rotateonelist()){
            int src = api.rotateonelist().src();
            int index = api.rotateonelist().index();
            Print_words({"rotateone src:", ToStr(src), ", index: ", ToStr(index), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            data[dst].assign(data[src].begin(), data[src].end());
            server_ctxts[dst] = server_context->EvalRotate(server_ctxts[src], index);
            index %= dataLen;
            if(index < 0) 
                std::rotate(data[dst].begin(), data[dst].begin() + dataLen + index, data[dst].end());
            else
                std::rotate(data[dst].begin(), data[dst].begin() + index, data[dst].end());
        }
        int level = server_ctxts[dst]->GetLevel();
        int noise = server_ctxts[dst]->GetNoiseScaleDeg();
        Print_words({"level:", ToStr(level), ", Noise:", ToStr(noise)}, 2, NO_STAR_LINE);
        maxLevel = std::max(maxLevel, level);
        if(argc >= 3 && argv[2][0] == 'c')
            PrintAndCheckResult(client_context, true);
        if(maxLevel > muldepth) 
            THROW_EXCEPTION("Need to increase muldepth.");
        print_one_star_line();
    }

    Print("server: evaluation done");
    server_serialize_result(result_fstream);
    client_decrypt_data(client_context, result_fstream);
    PrintAndCheckResult(client_context, true);
}catch(openfhe_error& e){
    THROW_EXCEPTION(e.what());
}
    if(isAllCorrect)
        Printf("client: all result is correct.\n");
    else
        THROW_EXCEPTION("client: some result is wrong.");
    return 0;
}