# create-test-data

This script is uses to generate transactions containing test domain data for use with cdnsd

To run it, you need to provide a few things:

* a Maestro API key for preprod
* the domain to create an entry for
* the nameservers for the domain
* the source address for the TX to generate (you must be able to sign TXes for this address)
* the destination address for the TX to generate (this will be consumed by cdnsd)

```
$ MAESTRO_API_KEY=xxxxxx ./create-test-data -D foo.cardano -n 1.2.3.4 -n 2.3.4.5 -s addr_test1qrldjljcfh6e8cg4z5uu6l7s7dccx5kyk0vppny2yldxqd0uts9m9rn7fhqnm3eluw8m8ytuupw4sjlrcnp2jlc2g8qsn9p8p0 -d addr_test1vpzje979n2swggeu24ehty8nka2fh7zu3jykfrazfwfff4c2yvx4d
```

Once the script generates the transaction, you'll need to import it into a wallet such as Eternl to sign and submit it.
