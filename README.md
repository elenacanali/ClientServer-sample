# ClientServer-sample

Simulation of Client-Server communication with SSL/TLS protocol.

The runnable class is the class Runner.java.

The initial panel ask the user to select the digital signature algorithm, the key agreement
algorithm and the supported ciphers of the server; after this operation the user confirm the
choices by the “Server Init” button. The user must select the supported cipher of the client
and confirm the choices by the “Client Init” button.
If something goes wrong, an error message is shown and the user can restart the procedure
using the pertinent button.

The second panel allow the user the communication between server and client. Using the
suitable box, the user can insert messages and send them to the counterpart. It is also
possible to switch the common cipher used during the computation, using the button
“Change cipher agreement with a random cipher” (the new common cipher can be the same
of the previous one).
