#include <iostream>
#include <fstream>
#include <vector>

int main() {
    const char* urandom_file = "/dev/urandom";
    const char* output_file = "random_data.bin";
    const int num_bytes = 32;
    std::ifstream urandom(urandom_file, std::ios::in | std::ios::binary);
    if (!urandom) {
        std::cerr << "Failed to open /dev/urandom" << std::endl;
        return 1;
    }
    std::vector<unsigned char> random_data(num_bytes);
    urandom.read(reinterpret_cast<char*>(&random_data[0]), num_bytes);
    if (urandom.gcount() != num_bytes) {
        std::cerr << "Failed to read random data" << std::endl;
        return 1;
    }
    urandom.close();
    std::ofstream outfile(output_file, std::ios::out | std::ios::binary);
    if (!outfile) {
        std::cerr << "Failed to open output file" << std::endl;
        return 1;
    }
    outfile.write(reinterpret_cast<char*>(&random_data[0]), num_bytes);
    if (!outfile) {
        std::cerr << "Failed to write random data to the output file" << std::endl;
        return 1;
    }
    outfile.close();
    return 0;
}