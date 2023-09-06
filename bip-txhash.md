```
  BIP: tbd
  Layer: Consensus (soft fork)
  Title: OP_TXHASH and OP_CHECKTXHASHVERIFY
  Author: Steven Roose <steven@roose.io>
  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-tbd
  Status: Draft
  Type: Standards Track
  Created: 2023-09-03
  License: BSD-3-Clause
```

# Abstract

This BIP proposes two new opcodes, `OP_CHECKTXHASHVERIFY`, to be activated
as a change to the semantics of `OP_NOP4` in legacy script, segwit and tapscript;
and OP_TXHASH, to be activated as a change to the semantics of `OP_SUCCESS189`
in tapscript only.

These opcodes provide a generalized method for introspecting certain details of
the spending transaction, which enables non-interactive enforcement of certain
properties of the transaction spending a certain UTXO.

The constructions specified in this BIP also open up the way for other
potential updates; see Motivation section for more details.


# Summary

## OP_CHECKTXHASHVERIFY

The first new opcode, `OP_CHECKTXHASHVERIFY`, redefines the `OP_NOP4` opcode (`0xb3`) as a soft fork upgrade.

It has the following semantics:

* There is at least one element on the stack, fail otherwise.
* The element on the stack is at least 32 bytes long, fail otherwise.
* The first 32 bytes are interpreted as the TxHash and the remaining suffix bytes specify the TxFieldSelector.
* If the TxFieldSelector is invalid, fail.
* The actual TxHash of the transaction at the current input index, calculated
  using the given TxFieldSelector must be equal to the first 32 bytes of the
  element on the stack, fail otherwise.


## OP_TXHASH

The second new opcode, `OP_TXHASH`, redefines the `OP_SUCCESS189` tapscript opcode (`0xbd`) as a soft fork upgrade.

It has the following semantics:

* There is at least one element on the stack, fail otherwise.
* The element is interpreted as the TxFieldSelector and is popped off the stack.
* If the TxFieldSelector is invalid, fail.
* The 32-byte TxHash of the transaction at the current input index, calculated
  using the given TxFieldSelector is pushed onto the stack.

## TxFieldSelector

The TxFieldSelector has the following semantics. We will give a brief conceptual
summary, followed by a reference implementation of the CalculateTxHash function.

* There are two special cases for the TxFieldSelector:
  * the empty value, zero bytes long: it is set equal to `TXFS_SPECIAL_TEMPLATE`,
    the de-facto default value which means everything except the prevouts and the prevout
    scriptPubkeys.

    Special case `TXFS_SPECIAL_TEMPLATE` is 4 bytes long, as follows:
    * &nbsp;1. `TXFS_ALL`
    * &nbsp;2. `TXFS_INPUTS_TEMPLATE | TXFS_OUTPUTS_ALL`
    * &nbsp;3. `TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL`
    * &nbsp;4. `TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL`

  * the `0x00` byte: it is set equal to `TXFS_SPECIAL_ALL`, which means "ALL" and is primarily
    useful to emulate `SIGHASH_ALL` when `OP_TXHASH` is used in combination
    with `OP_CHECKSIGFROMSTACK`.

    Special case `TXFS_SPECIAL_ALL` is 4 bytes long, as follows:
    * &nbsp;1. `TXFS_ALL`
    * &nbsp;2. `TXFS_INPUTS_ALL | TXFS_OUTPUTS_ALL`
    * &nbsp;3. `TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL`
    * &nbsp;4. `TXFS_INOUT_NUMBER | TXFS_INOUT_SELECTION_ALL`

* The first byte of the TxFieldSelector has its 8 bits assigned as follows, from lowest to highest:
  * &nbsp;1. version (`TXFS_VERSION`)
  * &nbsp;2. locktime (`TXFS_LOCKTIME`)
  * &nbsp;3. current input index (`TXFS_CURRENT_INPUT_IDX`)
  * &nbsp;4. current input control block (or empty) (`TXFS_CURRENT_INPUT_CONTROL_BLOCK`)
  * &nbsp;5. current input spent script (i.e. witness script or tapscript) (`TXFS_CURRENT_INPUT_SPENTSCRIPT`)
  * &nbsp;6. current script last `OP_CODESEPARATOR` position (or 0xffffffff)
    (`TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS`)
  * &nbsp;7. (unused)

* The last (highest) bit of the first byte (`TXFS_CONTROL`), we will call the
  "control bit", and it can be used to control the behavior of the opcode. For
  `OP_TXHASH` and `OP_CHECKTXHASHVERIFY`, the control bit is used to determine
  whether the TxFieldSelector itself has to be included in the resulting hash.
  (For potential other uses of the TxFieldSelector (like a hypothetical
  `OP_TX`), this bit can be repurposed.)

* If either "inputs" or "outputs" is set to 1, expect another byte with its 8
  bits assigning the following variables, from lowest to highest:
  * Specifying which fields of the inputs will be selected:
    * &nbsp;1. prevouts (`TXFS_INPUTS_PREVOUTS`)
    * &nbsp;2. sequences (`TXFS_INPUTS_SEQUENCES`)
    * &nbsp;3. scriptSigs (`TXFS_INPUTS_SCRIPTSIGS`)
    * &nbsp;4. prevout scriptPubkeys (`TXFS_INPUTS_PREV_SCRIPTPUBKEYS`)
    * &nbsp;5. prevout values (`TXFS_INPUTS_PREV_VALUED`)
    * &nbsp;6. taproot annexes (`TXFS_INPUTS_TAPROOT_ANNEXES`)

  * Specifying which fields of the outputs will be selected:
    * &nbsp;7. scriptPubkeys (`TXFS_OUTPUTS_SCRIPTPUBKEYS`)
    * &nbsp;8. values (`TXFS_OUTPUTS_VALUES`)

* We define as follows:
  * `TXFS_ALL = TXFS_VERSION | TXFS_LOCKTIME | TXFS_CURRENT_INPUT_IDX | TXFS_CURRENT_INPUT_CONTROL_BLOCK | TXFS_CURRENT_INPUT_LAST_CODESEPARATOR_POS | TXFS_INPUTS | TXFS_OUTPUTS | TXFS_CONTROL`
  * `TXFS_INPUTS_ALL = TXFS_INPUTS_PREVOUTS | TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS | TXFS_INPUTS_PREV_SCRIPTPUBKEYS | TXFS_INPUTS_PREV_VALUES | TXFS_INPUTS_TAPROOT_ANNEXES`
  * `TXFS_INPUTS_TEMPLATE = TXFS_INPUTS_SEQUENCES | TXFS_INPUTS_SCRIPTSIGS | TXFS_INPUTS_PREV_VALUES | TXFS_INPUTS_TAPROOT_ANNEXES`
  * `TXFS_OUTPUTS_ALL = TXFS_OUTPUTS_SCRIPTPUBKEYS | TXFS_OUTPUTS_VALUES`

For both inputs and then outputs, do the following:

* If the "in/outputs" field is set to 1, another additional byte is expected:
  * The highest bit (`TXFS_INOUT_NUMBER`) indicates whether the "number of in-/outputs"
    should be committed to.
  * For the remaining bits, there are three exceptional values:
    * 0x00 (`TXFS_INOUT_SELECTION_NONE`) means "no in/outputs"
      (hence only the number of them as `0x80` (`TXFS_INOUT_NUMBER`)).
    * `0x40` (`TXFS_INOUT_SELECTION_CURRENT`) means "select only the in/output of the current input index"
      (it is invalid when current index exceeds number of outputs).
    * `0x3f` (`TXFS_INOUT_SELECTION_ALL`) means "select all in/outputs".

  * The second highest bit (`TXFS_INOUT_SELECTION_MODE`) is the "specification mode":
    * Set to 0 it means "leading mode".
    * Set to 1 it means "individual mode".
  * In "leading mode", the third highest bit (`TXFS_INOUT_SELECTION_SIZE`) is
    used to indicate the "count size", i.e. the number of bytes will be used to
    represent the number of in/output.
    * With "index size" set to 0, the remaining lowest 5 bits of the first byte will
      be interpreted as the number of leading in/outputs to select.
    * With "index size" set to 1, the remaining lowest 5 bits of the first byte together with the
      8 bits of the next byte will be interpreted as the number of leading in/outputs to select.
  * In "individual mode", the remaining lowest 6 bits of the first byte will be
    interpreted as `n`, the number of individual in/outputs to select. For each
    individual input, (at least) one byte is expected, of this byte. The
    highest bit is used to indicate "absolute or relative" indices.
    * If the highest bit is set to 0, it is an absolute index. The second
      highest bit is used to indicate the amount of bytes are used to represent
      the index.
      * If the second-highest bit is 0, the remaining 6 bits represent the index to be selected.
      * If the second-highest bit is 1, the remaining 6 bits, together with the 8 bits of the next
        byte, represent the index to be selected.
    * If the highest bit is set to 1, it is a relative index. The second highest bit is used to
      indicate the sign of the index.
      * If the second-highest bit is set to 0, the remaining 6 bits represent the positive relative
        index to be selected.
      * If the second-highest bit is set to 1, the remaining 6 bits represent the negative relative
        index to be selected.

Effectively, this allows a user to select
* all in/outputs
* the current input index
* the leading in/outputs up to 8192
* up to 64 individually selected in/outputs
** using absolute indices up to 16384
** using indices relative to the current input index from -64 to +64.

The TxFieldSelector is invalid when
* a byte is expected but missing
* additional unexpected bytes are present
* index size is set to 1 while not being necessary
* a leading number of individual index is selected out of bounds of the in/outputs
* individual indices are duplicated or not in increasing order

These limitations are to avoid potential TxFieldSelector malleability. It is
however allowed to use leading mode where it could be "all". This
is important to allow for optional addition of extra inputs or outputs.

//TODO(stevenroose) should we disallow individual that could be leading?


## Resource limits

* For legacy scripts and segwit, we don't add any extra resource limitations,
  with the argumentation that `OP_CHECKTXHASHVERIFY` already requires the user
  to provide at least 32 bytes of extra transaction size, either in the input
  scriptSig, or the witness. Additional more complex hashes require additional
  witness bytes. Given that `OP_CAT` is not available in this context, if a
  malicious user tries to increase the number of TransactionHashes being
  calculated by using opcodes like `OP_DUP`, the TxFieldSelector for all these
  calculations is identical, so the calculation can be cached within the same
  transaction.

* For tapscript, primarily motivated by the cheaper opcode `OP_TXHASH` (it
  doesn't require an additional 32 witness bytes be provided) and the potential
  future addition of byte manipulation opcodes like `OP_CAT`, an additional
  cost is specified per TransactionHash execution. Using the same validation
  budget ("sigops budget") introduced in BIP-0342, each TransactionHash
  decreases the validation budget by 10. If this brings the budget below zero,
  the script fails immediately.<br>The following considerations should be made:
  * All fields that can be of arbitrary size are cachable as TransactionHash always hashes their hashed values.
  * In "individual mode", a user can at most commit 32 inputs or outputs,
    which we don't consider excessive for potential repeated use.
  * In "leading mode", a caching strategy can be used where the SHA256 context
    is stored every N in/outputs so that multiple executions of the
    TransactionHash function can use the caches and only have to hash an
    additional N-1 items at most.


# Motivation

This BIP specifies a basic transaction introspection primitive that is useful
to either reduce interactivity in multi-user protocols or to enforce some basic
constraints on transactions.

Additionally, the constructions specified in this BIP can lay the groundwork for
some potential future upgrades:
* The TxFieldSelector construction would work well with a hypothetical opcode
  `OP_TX` that allows for directly introspecting the transaction by putting the
  fields selected on the stack instead of hashing them together.
* The TransactionHash obtained by `OP_TXHASH` can be combined with a
  hypothetical opcode `OP_CHECKSIGFROMSTACK` to effectively create an
  incredibly flexible signature hash, which would enable constructions like
  `SIGHASH_ANYPREVOUT`.

## Comparing with some alternative proposals

* This proposal strictly generalizes BIP-119's `OP_CHECKTEMPLATEVERIFY`, as the
  default mode of our TxFieldSelector is effectively the same (though not
  byte-for-byte identical) as what `OP_CTV` acomplishes, without costing any
  additional bytes. Additionally, using `OP_CHECKTXHASHVERIFY` allows for more
  flexibility which can help in the case for
  * enabling adding fees to a transaction without breaking a multi-tx protocol;
  * multi-user protocols where users are only concerned about their own inputs and outputs.

* Constructions like `OP_IN_OUT_VALUE` used with `OP_EQUALVERIFY` can be
  emulated by two `OP_TXHASH` instances by using the TxFieldSelector to select
  a single input value first and a single output value second and enforcing
  equality on the hashes. Neither of these alternatives can be used to enforce
  small value differencials without the availability of 64-bit arithmetic in
  Script.

* Like mentioned above, `SIGHASH_ANYPREVOUT` can be emulated using `OP_TXHASH`
  when combined with `OP_CHECKSIGFROMSTACK`: 
  `<txfs> OP_TXHASH <pubkey> OP_CHECKSIGFROMSTACK` effectively emulates `SIGHASH_ANYPREVOUT`.


# Detailed Specification

A reference implementation in Rust is provided attached as part of this BIP
together with a JSON file of test vectors generated using the reference
implementation.


# Implementation

* A proposed implementation for Bitcoin Core is available here:
  https://github.com/bitcoin/bitcoin/pull/29050
* A proposed implementation for rust-bitcoin is available here:
  https://github.com/rust-bitcoin/rust-bitcoin/pull/2275

Both of the above implementations perform effective caching to avoid potential
denial-of-service attack vectors.


# Acknowledgement

Credit for this proposal mostly goes to Jeremy Rubin for his work on BIP-119's
`OP_CHECKTEMPLATEVERIFY` and to Russell O'Connor for the original idea of
generalizing `OP_CHECKTEMPLATEVERIFY` into `OP_TXHASH`.

Additional thanks to Andrew Poelstra, Greg Sanders, Rearden Code, Rusty Russell
and others for their feedback on the specification.

