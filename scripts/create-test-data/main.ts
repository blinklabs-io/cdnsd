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
  .option("-n, --nameserver <nameserver>", "Nameserver for domain, specified as a <hostname,ipaddress> pair (can be specified multiple times)", { collect: true, required: true })
  .option("-s, --source-address <address>", "Source wallet address to send from (you must be able to sign transactions for this)", { required: true })
  .option("-d, --dest-address <address>", "Destination wallet address to send to (this will be read by cdnsd)", { required: true })
  .action(async ({ maestroApiKey, domain, nameserver, sourceAddress, destAddress }) => {
    console.log(`Building transaction...`);

    const provider = new Maestro({
      network: "Preprod",
      apiKey: maestroApiKey,  // Get yours by visiting https://docs.gomaestro.org/docs/Getting-started/Sign-up-login.
      turboSubmit: false
    });
    const lucid = await Lucid.new(provider, "Preprod");

    lucid.selectWalletFrom({ address: sourceAddress });

    // TODO: update datum format
    const outDatum = new Constr(0, [
      fromText(domain),
      // [ Constr(0, ...), Constr(0, ...), ... ]
      nameserver.map(
        nameserver => new Constr(
          0,
          // Split nameserver hostname and IP address and convert both to bytestrings
          nameserver.split(",").map(
            nameserver => fromText(nameserver),
          ),
        ),
      ),
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
