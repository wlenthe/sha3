/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                                                                                 *
 * Copyright (c) 2016, William C. Lenthe                                           *
 * All rights reserved.                                                            *
 *                                                                                 *
 * Redistribution and use in source and binary forms, with or without              *
 * modification, are permitted provided that the following conditions are met:     *
 *                                                                                 *
 * 1. Redistributions of source code must retain the above copyright notice, this  *
 *    list of conditions and the following disclaimer.                             *
 *                                                                                 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,    *
 *    this list of conditions and the following disclaimer in the documentation    *
 *    and/or other materials provided with the distribution.                       *
 *                                                                                 *
 * 3. Neither the name of the copyright holder nor the names of its                *
 *    contributors may be used to endorse or promote products derived from         *
 *    this software without specific prior written permission.                     *
 *                                                                                 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"     *
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE       *
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE  *
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE    *
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      *
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR      *
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER      *
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,   *
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE   *
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.            *
 *                                                                                 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
 
#include "sha3.h"
#include <iostream>
#include <fstream>

int main() {
  //hash test vectors
  std::string testVector("abc");
  std::cout << "test vector - `" << testVector << "':\n";
  std::cout << "\t224: " << SHA3<224>::Digest(testVector) << "\n";
  std::cout << "\t256: " << SHA3<256>::Digest(testVector) << "\n";
  std::cout << "\t384: " << SHA3<384>::Digest(testVector) << "\n";
  std::cout << "\t512: " << SHA3<512>::Digest(testVector) << "\n\n";

  testVector.clear();
  std::cout << "test vector - `' (empty string):\n";
  std::cout << "\t224: " << SHA3<224>::Digest(testVector) << "\n";
  std::cout << "\t256: " << SHA3<256>::Digest(testVector) << "\n";
  std::cout << "\t384: " << SHA3<384>::Digest(testVector) << "\n";
  std::cout << "\t512: " << SHA3<512>::Digest(testVector) << "\n\n";

  testVector = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  std::cout << "test vector - `" << testVector << "':\n";
  std::cout << "\t224: " << SHA3<224>::Digest(testVector) << "\n";
  std::cout << "\t256: " << SHA3<256>::Digest(testVector) << "\n";
  std::cout << "\t384: " << SHA3<384>::Digest(testVector) << "\n";
  std::cout << "\t512: " << SHA3<512>::Digest(testVector) << "\n\n";

  testVector = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  std::cout << "test vector - `" << testVector << "':\n";
  std::cout << "\t224: " << SHA3<224>::Digest(testVector) << "\n";
  std::cout << "\t256: " << SHA3<256>::Digest(testVector) << "\n";
  std::cout << "\t384: " << SHA3<384>::Digest(testVector) << "\n";
  std::cout << "\t512: " << SHA3<512>::Digest(testVector) << "\n\n";

  testVector = std::string(1000000, 'a');
  std::cout << "test vector - `a' repeated 1 million times:\n";
  std::cout << "\t224: " << SHA3<224>::Digest(testVector) << "\n";
  std::cout << "\t256: " << SHA3<256>::Digest(testVector) << "\n";
  std::cout << "\t384: " << SHA3<384>::Digest(testVector) << "\n";
  std::cout << "\t512: " << SHA3<512>::Digest(testVector) << "\n\n";

  try {
    testVector.reserve(1073741824);
    testVector = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
    std::cout << "test vector - `" << testVector << "' repeated 16777216 times:\n";
    for(size_t i = 0; i < 24; i++) testVector.insert(testVector.end(), testVector.begin(), testVector.end());
    std::cout << "\t224: " << SHA3<224>::Digest(testVector) << "\n";
    std::cout << "\t256: " << SHA3<256>::Digest(testVector) << "\n";
    std::cout << "\t384: " << SHA3<384>::Digest(testVector) << "\n";
    std::cout << "\t512: " << SHA3<512>::Digest(testVector) << "\n\n";
  } catch (std::exception& e) {
    std::cout << "failed to allocate string for test vector\n";
  }

  //hash file
  std::string fileName;
  std::cout << "file: ";
  std::cin >> fileName;
  std::ifstream stream(fileName.c_str(), std::ios::in | std::ios::binary);
  if(stream.good()) {
    std::cout << "\t224: " << SHA3<224>::Digest(stream) << "\n";
    std::cout << "\t256: " << SHA3<256>::Digest(stream) << "\n";
    std::cout << "\t384: " << SHA3<384>::Digest(stream) << "\n";
    std::cout << "\t512: " << SHA3<512>::Digest(stream) << "\n";
  } else std::cout << "invalid file\n";
}
