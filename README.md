# Eth2Vec

## Overview
Eth2Vec is an analysis tool based on a neural network for natural language processing, and it outputs the existence and kind of vulnerabilities in a target smart contract code by only taking the code as input. 
Using Eth2Vec, you can analyze code of smart contracts quickly even without expert knowledge on smart contract vulnerabilities.
The paper of Eth2Vec is published on https://arxiv.org/abs/2101.02377.

![overview_eth2vec](https://github.com/fseclab-osaka/eth2vec/blob/main/images/overview_Eth2Vec.png)

## Install Instruction
We implemented Eth2Vec by utilizing **Kam1n0 version 2.0.0** (https://github.com/McGill-DMaS/Kam1n0-Community) and **py-solc-x** (https://pypi.org/project/py-solc-x/). 
You need to install Kam1n0 server before installing Eth2Vec.

### Install Kam1n0 server
1. Create clone of Kam1n0 (https://github.com/McGill-DMaS/Kam1n0-Community) onto your local.
2. Build Kam1n0 from the source code in `kam1n0`.

### Install selector of compiler of Solidity
3. Install py-solc-x (https://pypi.org/project/py-solc-x/).

### Install Eth2Vec
4. Create clone of Eth2Vec onto your local.
5. Copy `app` of Eth2Vec to `kam1n0/kam1n0-apps/src/main/java/ca/mcgill/sis/dmas/kam1n0` of Kam1n0.
6. Copy `bin` of Eth2Vec to `kam1n0/kam1n0-resources` of Kam1n0.
7. Copy `DisassemblyFactoryIDA.java` in `commons` of Eth2Vec to `kam1n0/kam1n0-commons/src/main/java/ca/mcgill/sis/dmas/kam1n0/impl/disassembly` of Kam1n0.
8. Copy `WinUtils.java` in `commons` of Eth2Vec to `kam1n0/kam1n0-commons/src/main/java/ca/mcgill/sis/dmas/env` of Kam1n0.
9. Copy `js` of Eth2Vec to `kam1n0/kam1n0-apps/target/classes/static` of Kam1n0.
10. Rebuild Kam1n0 with the copied files of Eth2Vec.
11. Run a main method in `Kam1n0-Community/kam1n0/kam1n0-cli/src/main/java/ca/mcgill/sis/dmas/kam1n0/cli/Main.java` with an argment `--start`.

### Vulnerabilities detection
We added the file assignVuln.py that takes in input the Kam1no output and assign the related vulnerabilities.

### EVM Extractor Update
We have updated the files corresponding to the EVM extractor,because  some dictionary key were deprecated. 
For examples we substituded the key 'children' with the key 'node', and the key 'constat' with 'isConstant'.
Also we test Eth2Vec with more recent Solidity contracts , pragma 0.8.0, and in order to parse correctly the input contract
we introduce a condition that check if the pragma version is >0.4 and ignore the deprecated keys that are no more usefull
on last version.


## License
This project is distributed under the Apache License Version 2.0. Please refer to LICENSE.txt for details.
