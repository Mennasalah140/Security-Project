Audio CTF Solution: The Mystery of Scrooge's Chest
Challenge Overview
We were presented with a series of encrypted audio files and cryptic clues leading to Scrooge McDuck's hidden treasure. The challenge involved three WAV files (output3.wav, output4.wav, output5.wav) and required careful analysis to uncover the hidden flag.

Key Clues and Initial Analysis
Provided Materials
note.txt: Contained poetic instructions with critical hints:

"Three vessels of sound" → Our three WAV files

"Twin artifacts" → Two identical files

"Use them for a single sacred joining" → Combine two files once

note.html: Featured a Gandalf "You shall not pass!" GIF, hinting at potential LOTR-themed solutions.

chest2.py: Suggested audio manipulation using pydub.

Critical Discovery
Through file comparison, we identified:

output3.wav and output5.wav were identical (MD5 hash match)

output4.wav was the unique file

This aligned perfectly with the "twin artifacts" clue, narrowing our approach to combining one twin with the unique file.

Solution Methodology
Phase 1: Audio Comparison Techniques
1. XOR Analysis
python
# Bitwise XOR comparison
xor_data = np.bitwise_xor(data1, data2)
Purpose: Highlight differences between files

Result: Revealed subtle modifications in the audio data

2. Phase Cancellation
python
inverted_audio = audio2.invert_phase()
phase_cancelled = audio1.overlay(inverted_audio)
Purpose: Cancel identical waveforms to isolate differences

Insight: Effective for finding hidden signals in similar audio

3. LSB Extraction
python
lsbs = samples & 1  # Get least significant bits
Purpose: Uncover data hidden in audio samples' LSBs

Finding: No immediately obvious flag in LSBs alone

Phase 2: Advanced Analysis
4. Spectrogram Examination
python
plt.specgram(data, Fs=rate, cmap='viridis', NFFT=2048)
Discovery: Visual patterns in frequency domain

Breakthrough: Revealed the flag in one combination's spectrogram

5. Reverse Audio Analysis
python
reversed_audio = audio.reverse()
Purpose: Catch hidden messages only audible when reversed

Result: No significant findings in this case

The Winning Approach
After systematic testing, the spectrogram of the XOR result between one twin and the unique file revealed:

KEY{THE_GREATER_WILL_SHALL_NOT_BE_DEFIED}
Why This Worked
The XOR operation amplified the hidden signal's visibility in the frequency domain

The spectrogram's color contrast made the text pattern apparent

This method respected the "use each file once" constraint

Key Takeaways
Start with basics: File comparison revealed identical twins

Follow the clues: "Twin artifacts" directed our combination strategy

Layered analysis: Required multiple techniques to uncover the solution

Visual examination: Spectrograms often reveal what ears can't hear

Constraints matter: Honoring the "use once" rule was crucial

RESOURCE: https://ctf-wiki.mahaloz.re/misc/audio/introduction/