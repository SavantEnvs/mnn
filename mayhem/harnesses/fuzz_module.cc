// Fuzz MNN's Express Module loader (model -> static/dynamic module graph) with a forward pass
// on zero-filled inputs.
#include <MNN/expr/Module.hpp>
#include <MNN/expr/ExprCreator.hpp>
#include <MNN/expr/Executor.hpp>
#include <MNN/expr/ExecutorScope.hpp>
#include <cstring>
#include <memory>
#include <vector>

using namespace MNN::Express;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return -1;
    }
    // flatbuffers requires an aligned model buffer; the fuzz input is offset by the mode byte.
    std::vector<uint8_t> model(data + 1, data + size);
    MNN::ScheduleConfig sched;
    sched.type      = MNN_FORWARD_CPU;
    sched.numThread = 1;
    std::shared_ptr<Executor::RuntimeManager> rtmgr(Executor::RuntimeManager::createRuntimeManager(sched));
    Module::Config config;
    config.dynamic      = (data[0] & 1) != 0;
    config.shapeMutable = (data[0] & 2) != 0;
    config.rearrange    = (data[0] & 4) != 0;
    std::shared_ptr<Module> module(
        Module::load(std::vector<std::string>{}, std::vector<std::string>{}, model.data(), model.size(), rtmgr, &config),
        Module::destroy);
    if (nullptr == module) {
        return -1;
    }
    auto info = module->getInfo();
    if (nullptr == info) {
        return 0;
    }
    std::vector<VARP> inputs;
    for (auto& i : info->inputs) {
        size_t count = 1;
        for (auto d : i.dim) {
            if (d <= 0 || count * (size_t)d > (1u << 20)) {
                return 0;
            }
            count *= (size_t)d;
        }
        auto v = _Input(i.dim, i.order, i.type);
        if (nullptr == v || nullptr == v->writeMap<uint8_t>()) {
            return 0;
        }
        ::memset(v->writeMap<uint8_t>(), 0, count * i.type.bytes());
        v->unMap();
        inputs.emplace_back(v);
    }
    auto outputs = module->onForward(inputs);
    for (auto& o : outputs) {
        if (o.get() != nullptr) {
            o->readMap<uint8_t>();
        }
    }
    return 0;
}
