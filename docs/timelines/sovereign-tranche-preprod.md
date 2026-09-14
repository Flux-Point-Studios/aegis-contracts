# Aegis sovereign tranche - proven live on Cardano preprod

Every on-chain transaction below was read back from Koios (https://preprod.koios.rest/api/v1) when this file was generated (2026-09-14 02:01:30 UTC); every refused transaction was confirmed absent from the chain. The contract is `sovereign_position` (script hash `16c5b867c6c75c7dd49072ad04d3afb8506362b5166be8bed1084464`).

Prints marked SYNTHETIC are test prices published to the shared preprod feed to trigger the barrier; they are not market moves.

## On chain, in block order

### 1. Launch - 2026-09-13 20:43:48 UTC (block 5173450, epoch 313)

Carve a right-sized 51.17 tADA UTxO to fund the reference-script publish

- tx `099e29788211a9f9cfc49e950c60f7fc566398d6be6fad555fc4058c747c6e0c`
- https://preprod.cexplorer.io/tx/099e29788211a9f9cfc49e950c60f7fc566398d6be6fad555fc4058c747c6e0c
- https://preprod.cardanoscan.io/transaction/099e29788211a9f9cfc49e950c60f7fc566398d6be6fad555fc4058c747c6e0c
- fee 0.165677 tADA

### 2. Launch - 2026-09-13 20:45:44 UTC (block 5173453, epoch 313)

Publish sovereign_position (script hash 16c5b867..., 11,278 B) as a reference script

- tx `d10b56fadc88557b8f4fb88a8627fe75514198527c096f17282f130a8711577a`
- https://preprod.cexplorer.io/tx/d10b56fadc88557b8f4fb88a8627fe75514198527c096f17282f130a8711577a
- https://preprod.cardanoscan.io/transaction/d10b56fadc88557b8f4fb88a8627fe75514198527c096f17282f130a8711577a
- fee 0.660853 tADA

### 3. Launch - 2026-09-13 20:49:53 UTC (block 5173467, epoch 313)

Mint the one-shot AEGIS_SOVEREIGN beacon (policy c39d259f...) into the Head UTxO, spending seed 839419...#1

- tx `34fbc39d5f99867adb75c72d753c4ff483156a247e94f0f2e5acea4179c13cf9`
- https://preprod.cexplorer.io/tx/34fbc39d5f99867adb75c72d753c4ff483156a247e94f0f2e5acea4179c13cf9
- https://preprod.cardanoscan.io/transaction/34fbc39d5f99867adb75c72d753c4ff483156a247e94f0f2e5acea4179c13cf9
- fee 0.205155 tADA

### 4. Setup - 2026-09-13 21:04:03 UTC (block 5173507, epoch 313)

Fund the underwriter and insured test accounts

- tx `b509187e80d9cf764bb031dd91f6deee9540c816f9a8e96302b7363fd8f5fca0`
- https://preprod.cexplorer.io/tx/b509187e80d9cf764bb031dd91f6deee9540c816f9a8e96302b7363fd8f5fca0
- https://preprod.cardanoscan.io/transaction/b509187e80d9cf764bb031dd91f6deee9540c816f9a8e96302b7363fd8f5fca0
- fee 0.184069 tADA

### 5. Price print - 2026-09-13 21:07:34 UTC (block 5173516, epoch 313)

Price print on the preprod ADA/USD feed at the live price (spot 209191) before sale A

- tx `82eef851649a69730b02fd0131265c39b65d8da5dff0ccc0a9a1c91dc256b184`
- https://preprod.cexplorer.io/tx/82eef851649a69730b02fd0131265c39b65d8da5dff0ccc0a9a1c91dc256b184
- https://preprod.cardanoscan.io/transaction/82eef851649a69730b02fd0131265c39b65d8da5dff0ccc0a9a1c91dc256b184
- fee 0.175445 tADA

### 6. Sale - 2026-09-13 21:08:53 UTC (block 5173524, epoch 313)

Position A sold: 40 tADA cover, strike 152613 (25% below the effective spot), premium 2.717543 tADA from the sovereign quote; C-leg escrowed under the underwriter's own stake credential

- tx `8eaa9985b2073644f9aa186a77baade741d1b59d60aa37422b0e4a69cf9e54ae`
- https://preprod.cexplorer.io/tx/8eaa9985b2073644f9aa186a77baade741d1b59d60aa37422b0e4a69cf9e54ae
- https://preprod.cardanoscan.io/transaction/8eaa9985b2073644f9aa186a77baade741d1b59d60aa37422b0e4a69cf9e54ae
- fee 1.946972 tADA

### 7. Price print - 2026-09-13 21:12:03 UTC (block 5173533, epoch 313)

Price print at the live price (spot 208765) before sale B

- tx `d12b61123b57b1023641d489e910647962dbcc702216e57a653cbc7d2896a508`
- https://preprod.cexplorer.io/tx/d12b61123b57b1023641d489e910647962dbcc702216e57a653cbc7d2896a508
- https://preprod.cardanoscan.io/transaction/d12b61123b57b1023641d489e910647962dbcc702216e57a653cbc7d2896a508
- fee 0.175445 tADA

### 8. Sale - 2026-09-13 21:13:38 UTC (block 5173538, epoch 313)

Position B sold: 40 tADA cover, 7-day term (the Expire proof)

- tx `b2436f6fafcb8dd2f6bdc243e2a0b88636829dd90febfeebe8c99001c78bcc07`
- https://preprod.cexplorer.io/tx/b2436f6fafcb8dd2f6bdc243e2a0b88636829dd90febfeebe8c99001c78bcc07
- https://preprod.cardanoscan.io/transaction/b2436f6fafcb8dd2f6bdc243e2a0b88636829dd90febfeebe8c99001c78bcc07
- fee 1.946972 tADA

### 9. Price print - 2026-09-13 21:19:55 UTC (block 5173552, epoch 313)

Price print at the live price before the stranger-input refusal attempt

- tx `c32ff13092a50b344f1b05925eddf090531cec00db4c504f55fa4a483cb8365b`
- https://preprod.cexplorer.io/tx/c32ff13092a50b344f1b05925eddf090531cec00db4c504f55fa4a483cb8365b
- https://preprod.cardanoscan.io/transaction/c32ff13092a50b344f1b05925eddf090531cec00db4c504f55fa4a483cb8365b
- fee 0.175445 tADA

### 10. Setup - 2026-09-13 21:22:26 UTC (block 5173556, epoch 313)

Top up the parties: two 50 tADA UTxOs to the underwriter and two 12 tADA to the insured

- tx `e8e2e20954eabcd9dc141e9a0887ac90763f4307d929231ca9eee641fac5dff5`
- https://preprod.cexplorer.io/tx/e8e2e20954eabcd9dc141e9a0887ac90763f4307d929231ca9eee641fac5dff5
- https://preprod.cardanoscan.io/transaction/e8e2e20954eabcd9dc141e9a0887ac90763f4307d929231ca9eee641fac5dff5
- fee 0.175489 tADA

### 11. Price print - 2026-09-13 21:27:58 UTC (block 5173575, epoch 313)

Price print at the live price before the stranger-input refusal

- tx `4ae483f4947044c9fd779369f31fe63e926c751bccad7b03c893ba26a8f761f1`
- https://preprod.cexplorer.io/tx/4ae483f4947044c9fd779369f31fe63e926c751bccad7b03c893ba26a8f761f1
- https://preprod.cardanoscan.io/transaction/4ae483f4947044c9fd779369f31fe63e926c751bccad7b03c893ba26a8f761f1
- fee 0.175445 tADA

### 12. Price print - 2026-09-13 21:32:17 UTC (block 5173590, epoch 313)

SYNTHETIC crash print (spot 151613, below A's strike) - first claim-in-waiting attempt, which the driver declined to submit

- tx `f56b68999bfda7f6c1ded81935175eec1c588bf0db948f0e17050f7d9aeb7e97`
- https://preprod.cexplorer.io/tx/f56b68999bfda7f6c1ded81935175eec1c588bf0db948f0e17050f7d9aeb7e97
- https://preprod.cardanoscan.io/transaction/f56b68999bfda7f6c1ded81935175eec1c588bf0db948f0e17050f7d9aeb7e97
- fee 0.175445 tADA

### 13. Price print - 2026-09-13 21:37:05 UTC (block 5173608, epoch 313)

SYNTHETIC crash print (spot 151613) for the claim-in-waiting refusal

- tx `d6cd87acb7f026e77408767a2be6dd254fe4845f131bbca397aa5b92eb783ea9`
- https://preprod.cexplorer.io/tx/d6cd87acb7f026e77408767a2be6dd254fe4845f131bbca397aa5b92eb783ea9
- https://preprod.cardanoscan.io/transaction/d6cd87acb7f026e77408767a2be6dd254fe4845f131bbca397aa5b92eb783ea9
- fee 0.175445 tADA

### 14. Price print - 2026-09-13 22:22:47 UTC (block 5173710, epoch 313)

SYNTHETIC crash print (spot 151613) after A's one-hour waiting period

- tx `6cd097adeb4448704037e562addeb8e96906038d96ddb7c2a6f309f029c13885`
- https://preprod.cexplorer.io/tx/6cd097adeb4448704037e562addeb8e96906038d96ddb7c2a6f309f029c13885
- https://preprod.cardanoscan.io/transaction/6cd097adeb4448704037e562addeb8e96906038d96ddb7c2a6f309f029c13885
- fee 0.175445 tADA

### 15. Claim - 2026-09-13 22:24:05 UTC (block 5173713, epoch 313)

Position A claimed: 40 tADA paid to the insured, 5.717543 tADA remainder to the underwriter, both position markers burned, observer attested the reading

- tx `517d67ac4c00015553b4ce9865be02182fc1abfd85a809f168f8f904d95bc077`
- https://preprod.cexplorer.io/tx/517d67ac4c00015553b4ce9865be02182fc1abfd85a809f168f8f904d95bc077
- https://preprod.cardanoscan.io/transaction/517d67ac4c00015553b4ce9865be02182fc1abfd85a809f168f8f904d95bc077
- fee 1.916456 tADA

### 16. Staking and governance - 2026-09-14 01:11:16 UTC (block 5174174, epoch 313)

Underwriter stake key registered and delegated to pool15ff3v8y3m3c0rj3dksaqjy4qaj6j89s97qdnayugcjp6cp5z6ug and drep1y2qn0rf74zdk3u8upx2yk8un7tlts5f33uvklx96gq5a32qmwj3xg; Koios counts the escrowed C-leg under that stake account

- tx `50e91c3934c75a5a7bc650eea3fcae59ed7b4338c8ede19e4ed410b8fb923e85`
- https://preprod.cexplorer.io/tx/50e91c3934c75a5a7bc650eea3fcae59ed7b4338c8ede19e4ed410b8fb923e85
- https://preprod.cardanoscan.io/transaction/50e91c3934c75a5a7bc650eea3fcae59ed7b4338c8ede19e4ed410b8fb923e85
- fee 0.174257 tADA

## Refused by the validator (never on chain)

Each was evaluated and then submitted; the evaluator and the node both refused it with a phase-2 script failure (`ValidationTagMismatch` / `PlutusFailure`), so no explorer holds it. The ids are the signed transactions the node refused.

- **forged-mint** (about 2026-09-13 21:14:35 UTC): A pair mint with no Head spent (MintPair without the beacon input). tx `fdc521b87f23ed7ccd8fa551984f01e64792f8487e3aa317b4b12091c95a62b0`
- **early-expire** (about 2026-09-13 21:15:24 UTC): Expire on position B before its expiry. tx `7ae92eaa4e5e3c99fe550d4aedd29abc526c0e43281af821045cd499c0f54b42`
- **stranger-input** (about 2026-09-13 21:29:03 UTC): An Underwrite carrying an input from a third party's key. tx `e5d06f4e1a654c62bf707438e8d80dc6ca0b6617918679a0d69a5187ff25c011`
- **claim-in-waiting** (about 2026-09-13 21:38:07 UTC): A Claim on position A inside its one-hour waiting period, with the barrier touched. tx `6f2f79af9063099f4b47aed665afcd2f4e34909d361320ebb96701d50d72663a`

## Still owed

- Expire on position B, after 2026-09-20 21:21:29 UTC
- First staking rewards on the underwriter's delegated stake account, from the start of epoch 317 (~2026-10-02), only if the pool mints blocks in epoch 315

## Links

- underwriter stake account: https://preprod.cexplorer.io/stake/stake_test1uq5fs8a604htrwcxfzrlm74y0qgj5c98e3v78s9cr0cq77q92qj3n
- head address: https://preprod.cexplorer.io/address/addr_test1wqtvtwr8cmr4clw5jpe26pxn47u9qcmzk5txh6976yyygeq8qrhnr
- beacon: https://preprod.cexplorer.io/asset/c39d259f02027885c5a5de33869261f067310b338be8208e4875fce941454749535f534f5645524549474e
