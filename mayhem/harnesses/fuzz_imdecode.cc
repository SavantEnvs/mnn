// Fuzz MNN's image decoder (stb_image based imdecode) for each read mode.
#include <cv/imgcodecs.hpp>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) {
        return -1;
    }
    static const int modes[] = {MNN::CV::IMREAD_GRAYSCALE, MNN::CV::IMREAD_COLOR, MNN::CV::IMREAD_ANYDEPTH};
    int flags = modes[data[0] % 3];
    std::vector<uint8_t> buf(data + 1, data + size);
    auto img = MNN::CV::imdecode(buf, flags);
    if (img.get() != nullptr) {
        img->readMap<uint8_t>();
    }
    return 0;
}
