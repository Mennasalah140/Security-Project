import numpy as np
from scipy.io import wavfile

def xor_wav(file1, file2, output_file):
    rate1, data1 = wavfile.read(file1)
    rate2, data2 = wavfile.read(file2)
    
    if rate1 != rate2 or len(data1) != len(data2):
        print("Warning: Sample rate or length mismatch. Trimming to shorter length.")
        min_len = min(len(data1), len(data2))
        data1, data2 = data1[:min_len], data2[:min_len]
    
    xor_data = np.bitwise_xor(data1, data2)
    wavfile.write(output_file, rate1, xor_data)

xor_wav("output3.wav", "output4.wav", "xor_result.wav")