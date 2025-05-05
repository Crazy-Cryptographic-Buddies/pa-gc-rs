# Benchmarking for Publicly Auditable Garbled Circuit

This is the PoC implementation of the paper 

**Publicly Auditable Garbled Circuit** *([ePrint](https://ia.cr/2025/772)) whose authors are San Ling, Chan Nam Ngo, Khai Hanh Tang, and Huaxiong Wang*.

**TL;DR.** We picked the basic blueprint of the actively secure Garbled Circuit protocol, namely, WRK17, which relies on V-MAC. We then adopted VOLEitH (with SoftSpokenOT) to make the utilized V-MAC public auditable. We obtained a Constant Round Publicly Auditable Garbled Circuit Protocol with inherited security and efficiency from both WRK17 and VOLEitH.

**Remark.**
There are potential improvements in KRRW18, DILO22, or CWYY23, but we see non-trivial composition of such improvements and VOLEitH, for example, they may require the Learning-Parity-With-Noise assumption, while SoftSpokenOT is incompatible with LPN. We leave such a composition to future work.

**PoC Notes.**
We instantiate our CRHF with blake3 and PRG with AES-128 (software). In our PoC, we make blackbox calls to the pre-processing ideal functionality and only simulate the interaction of PA and PB. As such, the reported pre-processing time and proving time are only with reference value (as a lower bound). We focus on providing a benchmark of the pre-processing communication cost of PA and PB; verification time, and the final proof size of our protocol.

**Experimental Settings and Benchmark Result**

We benchmarked with HP Z4 G4 Workstation (x64-based PC, 1 processor with 8 threads, Intel64 Family 6 Model 85 Stepping 4 GenuineIntel ~3600 Mhz), for AES-128 and SHA-256 circuits, at security levels 128- and 256-bit.

| Circuit | Security level |  Pre-processing time (s) | Proving time (s) | Verification time (s) | Pre-processing (MB) | Final Proof (incl. pre-processing) (MB) |
| -------- | -------- | -------- | -------- | -------- | -------- |-------- |
| AES-128     | 128     | 15.2     | 0.8     | 10.5     | 3.7     | 6.7     |
| AES-128     | 256     | 30.3     | 1.7     | 20.7     |6.6     | 12.5     |
| SHA-256     | 128     | 55     | 3.2     | 37.6     | 13     | 23.6     |
| SHA-256     | 256     | 102.5     | 6.1     | 72.1     |23     | 43.8     |


**References**

[**WRK17**] https://ia.cr/2017/030

[**KRRW18**] https://ia.cr/2018/578

[**DILO22**] https://ia.cr/2022/552

[**CWYY23**] https://ia.cr/2023/278

[**VOLEitH**] https://ia.cr/2023/996

**Corresponding Author.**
Khai Hanh Tang (khaihanhtang@gmail.com or khaihanh.tang@ntu.edu.sg)

**Acknowledgement.**
The work of San Ling, Khai Hanh Tang, and Huaxiong Wang was supported by Singapore Ministry of Education Academic Research Fund Tier 2 (Grant MOE-000623-00) and Ethereum Support Program (Grant FY24-1414-A).

