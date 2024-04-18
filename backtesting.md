Here we document vulnerabilities that can be found by ItyFuzz in 30 minute:

## BSC
You need set BSC Etherscan API keys to `BSC_ETHERSCAN_API_KEY` environmental variable before running. 

### SEAMAN
**Vulnerability: Fund Loss; Time Take: 0h-0m-3s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x6bc9b4976ba6f8C9574326375204eE469993D038,0x6637914482670f91F43025802b6755F27050b0a6,0xDB95FBc5532eEb43DeEd56c8dc050c930e31017e -c bsc --onchain-block-number 23467515 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### RES02
**Vulnerability: Price Manipulation; Time Take: 0h-0m-2s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE,0x05ba2c512788bd95cd6D61D3109c53a14b01c82A,0x1B214e38C5e861c56e12a69b6BAA0B45eFe5C8Eb,0xecCD8B08Ac3B587B7175D40Fb9C60a20990F8D21,0xeccd8b08ac3b587b7175d40fb9c60a20990f8d21,0x04C0f31C0f59496cf195d2d7F1dA908152722DE7,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c -c bsc --onchain-block-number 21948016 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### LPC
**Vulnerability: Fund Loss; Time Take: 0h-0m-4s**

Run
```
ityfuzz evm -t 0x1e813fa05739bf145c1f182cb950da7af046778d,0x1E813fA05739Bf145c1F182CB950dA7af046778d,0x2ecD8Ce228D534D8740617673F31b7541f6A0099,0xcfb7909b7eb27b71fdc482a2883049351a1749d7 -c bsc --onchain-block-number 19852596 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### BIGFI
**Vulnerability: Price Manipulation; Time Take: 0h-8m-31s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x28ec0B36F0819ecB5005cAB836F4ED5a2eCa4D13,0xd3d4B46Db01C006Fb165879f343fc13174a1cEeB,0xA269556EdC45581F355742e46D2d722c5F3f551a -c bsc --onchain-block-number 26685503 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### BEGO
**Vulnerability: Fund Loss; Time Take: 0h-0m-18s**

Run
```
ityfuzz evm -t 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x88503F48e437a377f1aC2892cBB3a5b09949faDd,0xc342774492b54ce5F8ac662113ED702Fc1b34972 -c bsc --onchain-block-number 22315679 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Yyds
**Vulnerability: Fund Loss; Time Take: 0h-0m-4s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x970A76aEa6a0D531096b566340C0de9B027dd39D,0xB19463ad610ea472a886d77a8ca4b983E4fAf245,0xd5cA448b06F8eb5acC6921502e33912FA3D63b12,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xe70cdd37667cdDF52CabF3EdabE377C58FaE99e9 -c bsc --onchain-block-number 21157025 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### EGD-Finance
**Vulnerability: Fund Loss; Time Take: 0h-0m-2s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x202b233735bF743FA31abb8f71e641970161bF98,0xa361433E409Adac1f87CDF133127585F8a93c67d,0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE,0x34Bd6Dba456Bc31c2b3393e499fa10bED32a9370,0xc30808d9373093fbfcec9e026457c6a9dab706a7,0x34bd6dba456bc31c2b3393e499fa10bed32a9370,0x93c175439726797dcee24d08e4ac9164e88e7aee -c bsc --onchain-block-number 20245522 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### BBOX
**Vulnerability: Price Manipulation; Time Take: 0h-0m-4s**

Run
```
ityfuzz evm -t 0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x5DfC7f3EbBB9Cbfe89bc3FB70f750Ee229a59F8c -c bsc --onchain-block-number 23106506 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### FAPEN
**Vulnerability: Fund Loss; Time Take: 0h-0m-2s**

Run
```
ityfuzz evm -t 0xf3f1abae8bfeca054b330c379794a7bf84988228,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xf3F1aBae8BfeCA054B330C379794A7bf84988228 -c bsc --onchain-block-number 28637846 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### AUR
**Vulnerability: Fund Loss; Time Take: 0h-5m-36s**

Run
```
ityfuzz evm -t 0x73A1163EA930A0a67dFEFB9C3713Ef0923755B78,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x70678291bDDfd95498d1214BE368e19e882f7614 -c bsc --onchain-block-number 23282134 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### LocalTrader2
**Vulnerability: Fund Loss; Time Take: 0h-16m-53s**

Run
```
ityfuzz evm -t 0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE,0xcE3e12bD77DD54E20a18cB1B94667F3E697bea06,0x5C65BAdf7F97345B7B92776b22255c973234EfE7,0x303554d4D8Bd01f18C6fA4A8df3FF57A96071a41,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c -c bsc --onchain-block-number 28460897 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Annex
**Vulnerability: Fund Loss; Time Take: 0h-5m-59s**

Run
```
ityfuzz evm -t 0xe65E970F065643bA80E5822edfF483A1d75263E3,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73 -c bsc --onchain-block-number 23165446 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### ARA
**Vulnerability: Arbitrary Call; Time Take: 0h-0m-5s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x7BA5dd9Bb357aFa2231446198c75baC17CEfCda9,0x13f4EA83D0bd40E75C8222255bc855a974568Dd4,0x5542958FA9bD89C96cB86D1A6Cb7a3e644a3d46e,0x98e241bd3be918e0d927af81b430be00d86b04f9,0x7ba5dd9bb357afa2231446198c75bac17cefcda9 -c bsc --onchain-block-number 29214010 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### PLTD
**Vulnerability: Price Manipulation; Time Take: 0h-10m-27s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0xD7B7218D778338Ea05f5Ecce82f86D365E25dBCE,0x4397C76088db8f16C15455eB943Dd11F2DF56545,0x29b2525e11BC0B0E9E59f705F318601eA6756645 -c bsc --onchain-block-number 22252045 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Sheep
**Vulnerability: Price Manipulation; Time Take: 0h-2m-5s**

Run
```
ityfuzz evm -t 0x0025B42bfc22CbbA6c02d23d4Ec2aBFcf6E014d4,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4,0x912DCfBf1105504fB4FF8ce351BEb4d929cE9c24 -c bsc --onchain-block-number 25543755 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### SUT
**Vulnerability: Arbitrary Call; Time Take: 0h-0m-0s**

Run
```
ityfuzz evm -t 0xF075c5C7BA59208c0B9c41afcCd1f60da9EC9c37,0x13f4EA83D0bd40E75C8222255bc855a974568Dd4,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xf075c5c7ba59208c0b9c41afccd1f60da9ec9c37,0x70E1bc7E53EAa96B74Fad1696C29459829509bE2,0x9be508ce41ae5795e1ebc247101c40da7d5742db -c bsc --onchain-block-number 30165901 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### ApeDAO
**Vulnerability: Price Manipulation; Time Take: 0h-0m-2s**

Run
```
ityfuzz evm -t 0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d,0x55d398326f99059fF775485246999027B3197955,0x45aa258ad08eeeb841c1c02eca7658f9dd4779c0,0xb47955b5b7eaf49c815ebc389850eb576c460092,0xee2a9D05B943C1F33f3920C750Ac88F74D0220c3,0xB47955B5B7EAF49C815EBc389850eb576C460092 -c bsc --onchain-block-number 30072293 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Axioma
**Vulnerability: Fund Loss; Time Take: 0h-0m-4s**

Run
```
ityfuzz evm -t 0x2C25aEe99ED08A61e7407A5674BC2d1A72B5D8E3,0xB6CF5b77B92a722bF34f6f5D6B1Fe4700908935E,0x6a3Fa7D2C71fd7D44BF3a2890aA257F34083c90f -c bsc --onchain-block-number 27620320 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### ValueDefi
**Vulnerability: Fund Loss; Time Take: 0h-13m-29s**

Run
```
ityfuzz evm -t 0x4269e4090FF9dFc99D8846eB0D42E67F01C3AC8b,0xD4BBF439d3EAb5155Ca7c0537E583088fB4CFCe8,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x7Af938f0EFDD98Dc513109F6A7E85106D26E16c4,0xd7D069493685A581d27824Fc46EdA46B7EfC0063 -c bsc --onchain-block-number 7223029 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Novo
**Vulnerability: Price Manipulation; Time Take: 0h-1m-21s**

Run
```
ityfuzz evm -t 0xEeBc161437FA948AAb99383142564160c92D2974,0xa0787daad6062349f63b7c228cbfd5d8a3db08f1,0x3463a663de4ccc59c8b21190f81027096f18cf2a,0x6Fb2020C236BBD5a7DDEb07E14c9298642253333,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x128cd0Ae1a0aE7e67419111714155E1B1c6B2D8D -c bsc --onchain-block-number 18225002 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### RADT
**Vulnerability: Price Manipulation; Time Take: 0h-10m-27s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0xDa26Dd3c1B917Fbf733226e9e71189ABb4919E3f,0xDC8Cb92AA6FC7277E3EC32e3f00ad7b8437AE883,0xaF8fb60f310DCd8E488e4fa10C48907B7abf115e,0x01112eA0679110cbc0ddeA567b51ec36825aeF9b -c bsc --onchain-block-number 21572418 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### LaunchZone
**Vulnerability: Arbitrary Call; Time Take: 0h-0m-13s**

Run
```
ityfuzz evm -t 0x6D8981847Eb3cc2234179d0F0e72F6b6b2421a01,0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56,0xDb821BB482cfDae5D3B1A48EeaD8d2F74678D593,0x3a6d8cA21D1CF76F653A67577FA0D27453350dD8,0x0ccee62efec983f3ec4bad3247153009fb483551,0x3B78458981eB7260d1f781cb8be2CaAC7027DbE2 -c bsc --onchain-block-number 26024419 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Thena
**Vulnerability: Price Manipulation; Time Take: 0h-0m-6s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x2952beb1326acCbB5243725bd4Da2fC937BCa087,0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d,0xF4C8E32EaDEC4BFe97E0F595AdD0f4450a863a11,0x39E29f4FB13AeC505EF32Ee6Ff7cc16e2225B11F,0x20a304a7d126758dfe6B243D0fc515F83bCA8431,0x618f9Eb0E1a698409621f4F487B563529f003643,0xA99c4051069B774102d6D215c6A9ba69BD616E6a -c bsc --onchain-block-number 26834149 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### PancakeHunny
**Vulnerability: Price Manipulation; Time Take: 0h-9m-59s**

Run
```
ityfuzz evm -t 0x12180BB36DdBce325b3be0c087d61Fce39b8f5A4,0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xb9b0090aaa81f374d66d94a8138d80caa2002950,0x109Ea28dbDea5E6ec126FbC8c33845DFe812a300,0x515Fb5a7032CdD688B292086cf23280bEb9E31B6,0x565b72163f17849832A692A3c5928cc502f46D69 -c bsc --onchain-block-number 7962338 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### BGLD
**Vulnerability: Price Manipulation; Time Take: 0h-2m-52s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0xE445654F3797c5Ee36406dBe88FBAA0DfbdDB2Bb,0x429339fa7A2f2979657B25ed49D64d4b98a2050d,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xC2319E87280c64e2557a51Cb324713Dd8d1410a3,0x169f715CaE1F94C203366a6890053E817C767B7C,0x559D0deAcAD259d970f65bE611f93fCCD1C44261,0x7526cC9121Ba716CeC288AF155D110587e55Df8b,0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4,0xC632F90affeC7121120275610BF17Df9963F181c -c bsc --onchain-block-number 23844529 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### HPAY
**Vulnerability: Fund Loss; Time Take: 0h-11m-38s**

Run
```
ityfuzz evm -t 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xF8bC1434f3C5a7af0BE18c00C675F7B034a002F0,0xC75aa1Fa199EaC5adaBC832eA4522Cff6dFd521A -c bsc --onchain-block-number 22280853 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### THB
**Vulnerability: Fund Loss; Time Take: 0h-1m-7s**

Run
```
ityfuzz evm -t 0x72e901F1bb2BfA2339326DfB90c5cEc911e2ba3C,0xae191Ca19F0f8E21d754c6CAb99107eD62B6fe53 -c bsc --onchain-block-number 21785004 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### CS
**Vulnerability: Price Manipulation; Time Take: 0h-0m-26s**

Run
```
ityfuzz evm -t 0x382e9652AC6854B56FD41DaBcFd7A9E633f1Edd5,0x55d398326f99059fF775485246999027B3197955,0x7EFaEf62fDdCCa950418312c6C91Aef321375A00,0x8BC6Ce23E5e2c4f0A96429E3C9d482d74171215e -c bsc --onchain-block-number 28466976 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Melo
**Vulnerability: Fund Loss; Time Take: 0h-0m-12s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x9A1aEF8C9ADA4224aD774aFdaC07C24955C92a54,0x6a8C4448763C08aDEb80ADEbF7A29b9477Fa0628 -c bsc --onchain-block-number 27960445 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### GSS
**Vulnerability: Price Manipulation; Time Take: 0h-8m-23s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0xB4F4cD1cc2DfF1A14c4Aaa9E9434A92082855C64,0x1ad2cB3C2606E6D5e45c339d10f81600bdbf75C0,0x37e42B961AE37883BAc2fC29207A5F88eFa5db66,0x69ed5b59d977695650ec4b29e61c0faa8cc0ed5c -c bsc --onchain-block-number 31108558 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### CFC
**Vulnerability: Fund Loss; Time Take: 0h-0m-24s**

Run
```
ityfuzz evm -t 0xdd9b223aec6ea56567a62f21ff89585ff125632c,0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d,0x55d398326f99059fF775485246999027B3197955,0x595488F902C4d9Ec7236031a1D96cf63b0405CF0,0x8213e87bb381919b292ace364d97d3a1ee38caa4,0xdd9B223AEC6ea56567A62f21Ff89585ff125632c,0x4d7Fa587Ec8e50bd0E9cD837cb4DA796f47218a1 -c bsc --onchain-block-number 29116478 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### cftoken
**Vulnerability: Price Manipulation; Time Take: 0h-0m-54s**

Run
```
ityfuzz evm -t 0x8B7218CF6Ac641382D7C723dE8aA173e98a80196,0x7FdC0D8857c6D90FD79E22511baf059c0c71BF8b -c bsc --onchain-block-number 16841980 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### AES
**Vulnerability: Price Manipulation; Time Take: 0h-0m-1s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3,0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907 -c bsc --onchain-block-number 23695904 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Utopia
**Vulnerability: Price Manipulation; Time Take: 0h-11m-26s**

Run
```
ityfuzz evm -t 0xfeEf619a56fCE9D003E20BF61393D18f62B0b2D5,0xb1da08c472567eb0ec19639b1822f578d39f3333,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x6191203510c2a6442faecdb6c7bb837a76f02d23,0xb1da08C472567eb0EC19639b1822F578d39F3333 -c bsc --onchain-block-number 30119396 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### MintoFinance
**Vulnerability: Fund Loss; Time Take: 0h-0m-1s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x0d116ed40831fef8e21ece57c8455ae3b1e4041b,0xdbf1c56b2ad121fe705f9b68225378aa6784f3e5,0xDbF1C56b2aD121Fe705f9b68225378aa6784f3e5,0x13f4EA83D0bd40E75C8222255bc855a974568Dd4,0x410a56541bD912F9B60943fcB344f1E3D6F09567,0xba91db0b31d60c45e0b03e6d515e45fcabc7b1cd -c bsc --onchain-block-number 30214253 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### BabyDogeCoin02
**Vulnerability: Fund Loss; Time Take: 0h-20m-22s**

Run
```
ityfuzz evm -t 0xc748673057861a797275CD8A068AbB95A902e8de,0x55d398326f99059fF775485246999027B3197955,0x4f3126d5DE26413AbDCF6948943FB9D0847d9818,0xA07c5b74C9B40447a954e1466938b865b6BBea36,0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56,0xC9a0F685F39d05D835c369036251ee3aEaaF3c47,0x9a6b926281b0c7bc4f775e81f42b13eda9c1c98e,0x95c78222B3D6e262426483D42CfA53685A67Ab9D,0x9869674E80D632F93c338bd398408273D20a6C8e,0xd8B6dA2bfEC71D684D3E2a2FC9492dDad5C3787F,0xc736cA3d9b1E90Af4230BD8F9626528B3D4e0Ee0,0x0536c8b0c3685b6e3C62A7b5c4E8b83f938f12D1,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0xfD36E2c2a6789Db23113685031d7F16329158384,0xfD5840Cd36d94D7229439859C0112a4185BC0255 -c bsc --onchain-block-number 29295010 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### MBC_ZZSH
**Vulnerability: Fund Loss; Time Take: 0h-0m-34s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x4E87880A72f6896E7e0a635A5838fFc89b13bd17,0x2170Ed0880ac9A755fd29B2688956BD959F933F8,0x5b1Bf836fba1836Ca7ffCE26f155c75dBFa4aDF1,0x33CCA0E0CFf617a2aef1397113E779E42a06a74A,0xeE04a3f9795897fd74b7F04Bb299Ba25521606e6 -c bsc --onchain-block-number 23474460 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### WGPT
**Vulnerability: Fund Loss; Time Take: 0h-0m-40s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0xe1272a840F574b68dE861eC5009784e3411cb96c,0xaa07222e4c3295C4E881ac8640Fbe5fB921D6840,0x81917eb96b397dFb1C6000d28A5bc08c0f05fC1d,0x5336a15f27b74f62cc182388c005df419ffb58b8,0x4f3126d5DE26413AbDCF6948943FB9D0847d9818,0x5a596eAE0010E16ed3B021FC09BbF0b7f1B2d3cD,0x1f415255f7E2a8546559a553E962dE7BC60d7942,0x1f415255f7e2a8546559a553e962de7bc60d7942 -c bsc --onchain-block-number 29891709 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### ROI
**Vulnerability: Fund Loss; Time Take: 0h-0m-1s**

Run
```
ityfuzz evm -t 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56,0xe48b75dc1b131fd3a8364b0580f76efd04cf6e9c,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x745D6Dd206906dd32b3f35E00533AD0963805124,0x216FC1D66677c9A778C60E6825189508b9619908,0xE48b75dc1b131fd3A8364b0580f76eFD04cF6e9c,0x158af3d23d96e3104bcc65b76d1a6f53d0f74ed0 -c bsc --onchain-block-number 21143795 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### HEALTH
**Vulnerability: Price Manipulation; Time Take: 0h-0m-3s**

Run
```
ityfuzz evm -t 0xF375709DbdE84D800642168c2e8bA751368e8D32,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x32B166e082993Af6598a89397E82e123ca44e74E,0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4 -c bsc --onchain-block-number 22337425 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Shadowfi
**Vulnerability: Price Manipulation; Time Take: 0h-29m-17s**

Run
```
ityfuzz evm -t 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x10bc28d2810dD462E16facfF18f78783e859351b,0xF9e3151e813cd6729D52d9A0C3ee69F22CcE650A -c bsc --onchain-block-number 20969095 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### MetaPoint
**Vulnerability: Fund Loss; Time Take: 0h-20m-18s**

Run
```
ityfuzz evm -t 0x5923375f1a732FD919D320800eAeCC25910bEdA3,0x55d398326f99059fF775485246999027B3197955,0x807d99bfF0bad97e839df3529466BFF09c09E706,0x8acb88F90D1f1D67c03379e54d24045D4F6dfDdB,0x435444d086649B846E9C912D21E1Bc651033A623,0x724DbEA8A0ec7070de448ef4AF3b95210BDC8DF6,0xA56622BB16F18AF5B6D6e484a1C716893D0b36DF,0xe8d6502E9601D1a5fAa3855de4a25b5b92690623,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x68531F3d3A20027ed3A428e90Ddf8e32a9F35DC8,0x9117df9aA33B23c0A9C2C913aD0739273c3930b3,0x52AeD741B5007B4fb66860b5B31dD4c542D65785,0xE5cBd18Db5C1930c0A07696eC908f20626a55E3C,0x3B5E381130673F794a5CF67FBbA48688386BEa86,0xC254741776A13f0C3eFF755a740A4B2aAe14a136 -c bsc --onchain-block-number 27264383 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### Carrot
**Vulnerability: Arbitrary Call; Time Take: 0h-0m-1s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x6863b549bf730863157318df4496eD111aDFA64f,0xcFF086EaD392CcB39C49eCda8C974ad5238452aC,0x5575406ef6b15eec1986c412b9fbe144522c45ae,0x6863b549bf730863157318df4496ed111adfa64f -c bsc --onchain-block-number 22055611 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### RES
**Vulnerability: Price Manipulation; Time Take: 0h-0m-3s**

Run
```
ityfuzz evm -t 0x55d398326f99059fF775485246999027B3197955,0x05ba2c512788bd95cd6D61D3109c53a14b01c82A,0x1B214e38C5e861c56e12a69b6BAA0B45eFe5C8Eb,0xff333de02129af88aae101ab777d3f5d709fec6f,0xeccd8b08ac3b587b7175d40fb9c60a20990f8d21,0x04C0f31C0f59496cf195d2d7F1dA908152722DE7,0x16b9a82891338f9bA80E2D6970FddA79D1eb0daE,0xecCD8B08Ac3B587B7175D40Fb9C60a20990F8D21 -c bsc --onchain-block-number 21948016 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```


### RFB
**Vulnerability: Fund Loss; Time Take: 0h-0m-16s**

Run
```
ityfuzz evm -t 0x26f1457f067bF26881F311833391b52cA871a4b5,0x03184AAA6Ad4F7BE876423D9967d1467220a544e,0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c,0x0fe261aeE0d1C4DFdDee4102E82Dd425999065F4 -c bsc --onchain-block-number 23649423 -f -i -p --onchain-etherscan-api-key $BSC_ETHERSCAN_API_KEY
```

