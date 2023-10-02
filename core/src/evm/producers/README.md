# Producer

The producer is the component that is responsible for producing information used by oracles.

### Lifecycle

Transactions finished execution  
=> `Producer.produce` is called (generates data)  
=> All `Oracle.oracle`s are called   
=> `Producer.notify_end` is called (remove cache)
