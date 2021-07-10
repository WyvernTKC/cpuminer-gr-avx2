#ifndef CRYPTONIGHT_H_
#define CRYPTONIGHT_H_

#ifdef __cplusplus
extern "C" {
#endif

// Helper functions for different types of Cryptonight variants.
void cryptonight_dark_hash(const void *input, void *output);
void cryptonight_darklite_hash(const void *input, void *output);
void cryptonight_fast_hash(const void *input, void *output);
void cryptonight_lite_hash(const void *input, void *output);
void cryptonight_turtle_hash(const void *input, void *output);
void cryptonight_turtlelite_hash(const void *input, void *output);

void cryptonight_dark_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1);
void cryptonight_darklite_2way_hash(const void *input0, const void *input1,
                                    void *output0, void *output1);
void cryptonight_fast_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1);
void cryptonight_lite_2way_hash(const void *input0, const void *input1,
                                void *output0, void *output1);
void cryptonight_turtle_2way_hash(const void *input0, const void *input1,
                                  void *output0, void *output1);
void cryptonight_turtlelite_2way_hash(const void *input0, const void *input1,
                                      void *output0, void *output1);

#ifdef __AVX2__

void cryptonight_dark_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3);
void cryptonight_darklite_4way_hash(const void *input0, const void *input1,
                                    const void *input2, const void *input3,
                                    void *output0, void *output1, void *output2,
                                    void *output3);
void cryptonight_fast_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3);
void cryptonight_lite_4way_hash(const void *input0, const void *input1,
                                const void *input2, const void *input3,
                                void *output0, void *output1, void *output2,
                                void *output3);
void cryptonight_turtle_4way_hash(const void *input0, const void *input1,
                                  const void *input2, const void *input3,
                                  void *output0, void *output1, void *output2,
                                  void *output3);
void cryptonight_turtlelite_4way_hash(const void *input0, const void *input1,
                                      const void *input2, const void *input3,
                                      void *output0, void *output1,
                                      void *output2, void *output3);

#endif // AVX2

#ifdef __cplusplus
}
#endif

#endif // CRYPTONIGHT_H_
