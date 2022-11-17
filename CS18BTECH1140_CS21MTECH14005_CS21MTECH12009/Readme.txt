#####################################################

--> Task 2:

1. Start Bob:
make run
For --> Enter PEM Pass Phrase: bob123

2. Start Alice:
make run
For --> Enter PEM Pass Phrase: alice123

To end the chat, please type in chat_close from Alice

####################################################

--> Task 3:

1. Start Bob:
make run

2. Start Trudy:
make run_downgrade

3. Start Alice:
make run

To end the chat, please type in chat_close from Alice

##################################################

--> Task 4:

1. Start Bob:
make run

2. Start Trudy:
make run_mitm

3. Start Alice:
make run

------While establishing 2 TLS pipes--------

For True Alice to Fake Bob:
1. For --> Enter PEM Pass Phrase in Trudy: bob123
2. For --> Enter PEM Pass Phrase in Alice: alice123

Again for Fake Alice to True Bob:
1. For --> Enter PEM Pass Phrase in Trudy: alice123
2. For --> Enter PEM Pass Phrase in Bob: bob123

To end the chat, please type in chat_close from Alice

#################################################