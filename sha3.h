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

#ifndef _SHA3H_
#define _SHA3H_

#include <cstdint>
#include <array>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <limits>
#include <cassert>

template <std::size_t NBits> class SHA3 {
	public:
		static std::string Digest(std::string input) {
			std::stringstream ss(input);
			return Digest(ss);
		}

		static std::string Digest(std::istream& input) {
			//read chunks and process until the end of the stream is reached
			std::array<std::uint64_t, 25> state = {0x0000000000000000};
			std::array<std::uint64_t, 25 - NBits / 32> block;
			const std::size_t blockBytes = block.size() * 8;
			std::uint8_t* byteBlock = reinterpret_cast<std::uint8_t*>(block.data());
			while(input.read((char*) byteBlock, blockBytes)) Absorb(block, state);

			//pad to next full block with 0x06 ...0x00... 0x80 (or 0x86 if only 1 padding byte)
			std::size_t danglingBytes = input.gcount();
			byteBlock[danglingBytes] = 0x06;
			for(std::size_t i = danglingBytes + 1; i < blockBytes; i++) byteBlock[i] = 0x00;
			byteBlock[blockBytes - 1] ^= 0x80;
			Absorb(block, state);

			//convert to text
			std::stringstream hash;
			hash << std::hex << std::setfill('0');
			for(std::size_t i = 0; i < NBits / 64; i++)
				hash << std::setw(16) << (IsBigEndian() ? state[i] : U64Swap(state[i]));

			//handle half word if needed
			if(32 == NBits % 64)
				hash << std::setw(8) << ((IsBigEndian() ? state[NBits / 64] : U64Swap(state[NBits / 64])) >> 32 & 0x00000000FFFFFFFF);
			return hash.str();
		}

	private:
		static_assert(NBits == 224 || NBits == 256 || NBits == 384 || NBits == 512, "SHA3 accepts 224, 256, 384, or 512 bits");
		static_assert(std::numeric_limits<unsigned char>::digits == 8, "SHA3 requires 8 bits per byte");

		static inline bool IsBigEndian() {
			static const union {
				std::uint64_t i;
				char c[8];
			} u = {0x0102030405060708};
			return (1 == u.c[0]);
		}

		static inline std::uint64_t U64Swap(std::uint64_t value) {
			return (((value) & 0xFF00000000000000) >> 56) |
			       (((value) & 0x00FF000000000000) >> 40) |
			       (((value) & 0x0000FF0000000000) >> 24) |
			       (((value) & 0x000000FF00000000) >> 8 ) |
			       (((value) & 0x00000000FF000000) << 8 ) |
			       (((value) & 0x0000000000FF0000) << 24) |
			       (((value) & 0x000000000000FF00) << 40) |
			       (((value) & 0x00000000000000FF) << 56);
		}

		static inline std::uint64_t U64RotateLeft(std::uint64_t value, const std::uint8_t& shift) {return (value << shift) | (value >> (64 - shift));}

		static inline void Absorb(const std::array<std::uint64_t, 25 - NBits / 32>& block, std::array<std::uint64_t, 25>& state) {
			const std::array<std::uint8_t, 24> permute = {1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18, 17, 11, 7, 10};
			const std::array<std::uint8_t, 24> triangle = {44, 20, 61, 39, 18, 62, 43, 25, 8, 56, 41, 27, 14, 2, 55, 45, 36, 28, 21, 15, 10, 6, 3, 1};//triangle numbers 24 through 1 % 64 (periodic shifts)
			const std::array<std::uint64_t, 24> registerShift = {
				0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
				0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
				0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
				0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
			};

			//incorporate new data into hash state and update
			for(std::size_t i = 0; i < block.size(); i++) state[i] ^= IsBigEndian() ? U64Swap(block[i]) : block[i];
			for (std::size_t i = 0; i < 24; i++) {
				//theta
				std::array<std::uint64_t, 5> columnParity;
				for(std::size_t j = 0; j < 5; j++)
					columnParity[j] = state[j] ^ state[j + 5] ^ state[j + 10] ^ state[j + 15] ^ state[j + 20];

				for(std::size_t j = 0; j < 5; j++) {
					std::uint64_t x = columnParity[(j + 4) % 5] ^ U64RotateLeft(columnParity[(j + 1) % 5], 1);
					for(std::size_t k = 0; k < 5;  k++)
						state[j + 5 * k] ^= x;
				}

				//rho + pi
				std::uint64_t temp = state[permute.front()];
				for(std::size_t j = 0; j < 23; j++) state[permute[j]] = U64RotateLeft(state[permute[j + 1]], triangle[j]);
				state[permute.back()] = U64RotateLeft(temp, triangle.back());

				//chi
				for(std::size_t j = 0; j < 25; j += 5) {
					std::uint64_t x = state[j];
					std::uint64_t y = state[j + 1];
					state[j + 0] ^= ~y& state[j + 2];
					state[j + 1] ^= ~state[j + 2] & state[j + 3] ;
					state[j + 2] ^= ~state[j + 3] & state[j + 4];
					state[j + 3] ^= ~state[j + 4] & x;
					state[j + 4] ^= ~x & y;
				}

				//iota
				state[0] ^= registerShift[i];
			}
		}
};

#endif
