#include "openfhe_test.h"

int main(int argc, char **argv){
    Print("--------------------- OpenFHE BGV ---------------------");
    // start = std::chrono::high_resolution_clock::now();
    std::random_device rd;
    string info_fileName = "info" + ToStr(rd());
    string result_fileName = "result" + ToStr(rd());
    info_fstream.open(info_fileName, std::ios::trunc | std::ios::in | std::ios::out | std::ios::binary);
    if(!info_fstream.is_open()) 
        ERROR_EXIT("client error: fail to open file to save context");

try{
    client_init_context(argv[1]);
    getTime();
    client_encrypt_data();
    getTime();
    server_init_context();
    getTime();
    std::remove(info_fileName.c_str());
    for(auto api : msg.apisequence().apilist()){
        int dst = api.dst();
        if(api.has_addtwolist()){
            int src1 = api.addtwolist().src1();
            int src2 = api.addtwolist().src2();
            Print_words({"addtwo src1:", ToStr(src1), ", src2: ", ToStr(src2), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_add(data[src1], data[src2], data[dst]);
            server_ctxts[dst] = server_context->EvalAdd(server_ctxts[src1], server_ctxts[src2]);
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
        }else if(api.has_multwolist()){
            int src1 = api.multwolist().src1();
            int src2 = api.multwolist().src2();
            Print_words({"multwo src1:", ToStr(src1), ", src2: ", ToStr(src2), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            vector_mul(data[src1], data[src2], data[dst]);
            server_ctxts[dst] = server_context->EvalMult(server_ctxts[src1], server_ctxts[src2]);
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
        }else if(api.has_rotateonelist()){
            int src = api.rotateonelist().src();
            int index = api.rotateonelist().index();
            Print_words({"rotateone src:", ToStr(src), ", index: ", ToStr(index), ", dst: ", ToStr(dst)}, 1, NO_STAR_LINE);
            data[dst].assign(data[src].begin(), data[src].end());
            server_ctxts[dst] = server_context->EvalRotate(server_ctxts[src], index);
            index %= dataLen / 2;
            if(index < 0) 
                std::rotate(data[dst].begin(), data[dst].begin() + dataLen / 2  + index, data[dst].begin() + dataLen / 2);
            else
                std::rotate(data[dst].begin(), data[dst].begin() + index, data[dst].begin() + dataLen / 2);
        }
        int level = server_ctxts[dst]->GetLevel();
        Print_words({"level:", ToStr(level)}, 2, NO_STAR_LINE);
        getTime();
        maxLevel = std::max(maxLevel, level);
        if(argc >= 3 && argv[2][0] == 'c')
            PrintAndCheckResult(true);
        if(maxLevel > muldepth) 
            THROW_EXCEPTION("Need to increase muldepth.");
        print_one_star_line();
    }
    Print("server: evaluation done");
    result_fstream.open(result_fileName, std::ios::trunc | std::ios::in | std::ios::out | std::ios::binary);
    if(!result_fstream.is_open())
        ERROR_EXIT("server error: fail to open file to save ctxt");
    server_serialize_result();
    getTime();
    client_decrypt_data();
    getTime();
    std::remove(result_fileName.c_str());
    PrintAndCheckResult(true);
    getTime();
}catch(openfhe_error& e){
    std::remove(info_fileName.c_str());
    std::remove(result_fileName.c_str());
    THROW_EXCEPTION(e.what());
}
    if(isAllCorrect)
        Printf("client: all result is correct.\n");
    else
        THROW_EXCEPTION("client: some result is wrong.");
    return 0;
}