import hre from "hardhat";
import "dotenv/config";

async function main() {
  if (!process.env.CONTRACT_ADDRESS || !process.env.DEPLOYER_ADDRESS) {
    throw new Error(
      "CONTRACT_ADDRESS and DEPLOYER_ADDRESS must be set in .env file"
    );
  }

  const contractAddress = process.env.CONTRACT_ADDRESS.toLowerCase();
  const deployerAddress = process.env.DEPLOYER_ADDRESS;
  const provider = hre.ethers.provider;
  const network = await provider.getNetwork();

  console.log(`\nSearching for deployment on ${network.name}...`);
  console.log(`Contract address: ${contractAddress}`);
  console.log(`Deployer address: ${deployerAddress}`);

  // Get deployer contract instance
  const deployer = await hre.ethers.getContractAt("Deployer", deployerAddress);

  // Get all Deploy events
  const filter = deployer.filters.Deploy();
  const events = await deployer.queryFilter(filter);

  // Find the event for our contract
  const deployEvent = events.find((event) => {
    const addr = event.args?.addr?.toLowerCase();
    return addr === contractAddress;
  });

  if (deployEvent) {
    const block = await provider.getBlock(deployEvent.blockNumber);
    if (!block) {
      throw new Error(`Block ${deployEvent.blockNumber} not found`);
    }

    console.log(
      `${network.name},${deployEvent.blockNumber},${new Date(
        Number(block.timestamp) * 1000
      ).toISOString()}`
    );
    return deployEvent.blockNumber;
  } else {
    console.log(`${network.name},not_found,not_found`);
    return null;
  }
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

export { main as getDeploymentBlock };
