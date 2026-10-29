// Fuzz MNN's flatbuffer model loader + CPU session creation + one forward pass.
#include <MNN/Interpreter.hpp>
#include <MNN/Tensor.hpp>
#include <MNN/MNNForwardType.h>
#include <memory>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::unique_ptr<MNN::Interpreter> net(MNN::Interpreter::createFromBuffer(data, size));
    if (nullptr == net) {
        return -1;
    }
    MNN::ScheduleConfig cfg;
    cfg.type      = MNN_FORWARD_CPU;
    cfg.numThread = 1;
    auto session  = net->createSession(cfg);
    if (nullptr == session) {
        return 0;
    }
    net->runSession(session);
    return 0;
}
