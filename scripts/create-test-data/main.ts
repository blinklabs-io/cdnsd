import { loadSync } from "https://deno.land/std@0.199.0/dotenv/mod.ts";
import { Command } from "https://deno.land/x/cliffy@v1.0.0-rc.3/command/mod.ts";
import {
  Constr,
  Data,
  fromText,
  toHex,
  Lucid,
  Maestro,
} from "https://deno.land/x/lucid@0.10.7/mod.ts";

loadSync({ export: true, allowEmptyValues: true });

const generate = new Command()
  .description("Generate an unsigned TX with the test domain data")
  .env("MAESTRO_API_KEY=<value:string>", "Maestro API key", { required: true })
  .option("-D, --domain <domain>", "Domain to create test data for", { required: true })
  .option("-n, --nameserver <nameserver>", "Nameserver for domain, specified as: <name>,<ipaddr> (can be specified multiple times)", { collect: true, required: true })
  .option("-r, --record <record>", "Record for domain, specified as: <name>[,<ttl>],<type>,<value> (can be specified multiple times)", { collect: true })
  .option("-s, --source-address <address>", "Source wallet address to send from (you must be able to sign transactions for this)", { required: true })
  .option("-d, --dest-address <address>", "Destination wallet address to send to (this will be read by cdnsd)", { required: true })
  .action(async ({ maestroApiKey, domain, nameserver, record, sourceAddress, destAddress }) => {
    // Merge --nameserver and --record values
    let records = []
    for (var tmpNameserver of nameserver) {
      const tmpNameserverParts = tmpNameserver.split(",")
      // Nameservers for a domain need both a NS record on the domain and an A record for themselves
      records.push(`${domain},ns,${tmpNameserverParts[0]}`)
      records.push(`${tmpNameserverParts[0]},a,${tmpNameserverParts[1]}`)
    }
    for (var tmpRecord in record) {
      records.push(tmpRecord)
    }

    console.log(`Building transaction...`);

    const provider = new Maestro({
      network: "Preprod",
      apiKey: maestroApiKey,  // Get yours by visiting https://docs.gomaestro.org/docs/Getting-started/Sign-up-login.
      turboSubmit: false
    });
    const lucid = await Lucid.new(provider, "Preprod");

    lucid.selectWalletFrom({ address: sourceAddress });

    let outDatumRecords = []
    records.forEach((tmpRecord) => {
      const recordParts = tmpRecord.split(",")
      if (recordParts.length == 3) {
        outDatumRecords.push(new Constr(
          1,
          [
            fromText(recordParts[0]),
	    fromText(recordParts[1]),
	    fromText(recordParts[2]),
          ],
        ))
      } else if (recordParts.length == 4) {
        outDatumRecords.push(new Constr(
          1,
          [
            fromText(recordParts[0]),
	    BigInt(parseInt(recordParts[1])),
	    fromText(recordParts[2]),
	    fromText(recordParts[3]),
          ],
        ))
      } else {
        console.log(`Invalid record: ${tmpRecord}`)
	Deno.exit(1)
      }
    })

    const outDatum = new Constr(1, [
      fromText(domain),
      outDatumRecords,
    ]);

    const outDatumEncoded = Data.to(outDatum);

    //console.log(`outDatumEncoded = ${outDatumEncoded}`)

    try {
      const txOut = await lucid
        .newTx()
        .payToAddressWithData(
          destAddress,
          { inline: outDatumEncoded },
          { lovelace: 2_000_000 },
        )
        // 10 minutes
        .validTo(Date.now() + 600_000)
        .complete();

      const txJsonObj = {
        "type": "Tx BabbageEra",
        "description": "unsigned",
        "cborHex": txOut.toString(),
      };
      console.log(`\nTX (unsigned):\n`);
      console.log(JSON.stringify(txJsonObj));
      console.log(`\nNOTE: you must import this transaction into a wallet such as Eternl to sign and submit it`);
    } catch (e) {
      console.log(e);
    }
  });

await new Command()
  .name("create-test-data")
  .description("Create test domain data for cdnsd")
  .command("generate", generate)
  .parse(Deno.args);
