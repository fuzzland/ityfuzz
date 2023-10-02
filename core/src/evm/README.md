## Workflow

Initialization:
* Add all function calls with default to corpus
* Deploy the contract
* Analyze the contract and extract all constants
* Setup callers

Execute one input:
```
Input -> REVM -- Reverted -----> Discard
              -- Control Leak -> Save the post execution state
              -- Success ------> Execute Producer -> Oracle
```

For every opcode executed in REVM, middleware is invoked. 
Middlewares are responsible for:
* `OnChain`: Fetching storage slot (when read) and bytecode (when called) from blockchain RPC on the fly
* `Flashloan`: Supporting logic for flashloan
* `InstructionCoverage`: Collect instruction coverage, only used in replay mode
* `Concolic`: Concolic execution

## WTF is Control Leak

Control leak happens when the execution is yielded to the caller while the execution is not yet
finished. 

Example:
```
contract A {
    function foo() public {
        bar();
        msg.sender.call("");
        baz();
    }
}
```

When `foo` is called, the execution is yielded to the caller after `bar` is executed (a control leak 
occurs). If the caller is a malicious contract, it can do anything between `bar` and `baz`. 

When ItyFuzz encounters a control leak, it will save the post execution so that ItyFuzz can continue the execution
or execute any new transaction before the execution is finished.
In the example, ItyFuzz will save the post execution state after `bar` is executed (stuffs for executing `baz`). 
Then, ItyFuzz will either choose to continue the execution or execute any new transaction before `baz` is executed.
