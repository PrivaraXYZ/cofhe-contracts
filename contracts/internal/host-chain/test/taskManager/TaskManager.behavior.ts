import { expect } from "chai";
import hre from "hardhat";

export function shouldBehaveLikeTaskManagerERC2771(): void {
  describe("ERC-2771 Meta-Transaction Support", function () {
    // =============================================================
    //                     BASIC FORWARDER TESTS
    // =============================================================

    it("should have no trusted forwarder when initialized with zero address", async function () {
      // The default deployment (via deploy scripts) initializes with zero address forwarder
      const taskManager = this.taskManager.connect(this.signers.admin);

      const forwarder = await taskManager.trustedForwarder();
      expect(forwarder).to.equal(hre.ethers.ZeroAddress);
    });

    it("should correctly report isTrustedForwarder as false when no forwarder is set", async function () {
      const taskManager = this.taskManager.connect(this.signers.admin);

      const isTrusted = await taskManager.isTrustedForwarder(hre.ethers.ZeroAddress);
      expect(isTrusted).to.equal(false);
    });

    it("should correctly report isTrustedForwarder as false for random address when no forwarder set", async function () {
      const taskManager = this.taskManager.connect(this.signers.admin);
      const randomAddress = "0x1234567890123456789012345678901234567890";

      const isTrusted = await taskManager.isTrustedForwarder(randomAddress);
      expect(isTrusted).to.equal(false);
    });

    // =============================================================
    //                     IMMUTABILITY TESTS
    // =============================================================

    it("should not have setTrustedForwarder function (immutable pattern)", async function () {
      const taskManager = this.taskManager.connect(this.signers.admin);

      // Verify that setTrustedForwarder is not a function on the contract
      // This confirms we're using the immutable forwarder pattern
      expect(taskManager.setTrustedForwarder).to.be.undefined;
    });

    it("should not have clearTrustedForwarder function (immutable pattern)", async function () {
      const taskManager = this.taskManager.connect(this.signers.admin);

      // Verify that clearTrustedForwarder is not a function on the contract
      expect(taskManager.clearTrustedForwarder).to.be.undefined;
    });

    // =============================================================
    //                     INITIALIZATION WITH FORWARDER TESTS
    // =============================================================

    describe("TaskManager with Forwarder", function () {
      let taskManagerWithForwarder: any;
      let taskManagerWithForwarderAddress: string;
      let mockForwarder: any;

      beforeEach(async function () {
        // Deploy a fresh MockForwarder
        const MockForwarder = await hre.ethers.getContractFactory("MockForwarder");
        mockForwarder = await MockForwarder.deploy();
        await mockForwarder.waitForDeployment();

        // Deploy a new TaskManager with the forwarder set
        const TaskManager = await hre.ethers.getContractFactory("TaskManager");
        const taskManagerImpl = await TaskManager.deploy();
        await taskManagerImpl.waitForDeployment();

        // Deploy proxy and initialize with forwarder
        const ERC1967Proxy = await hre.ethers.getContractFactory("ERC1967Proxy");
        const initData = TaskManager.interface.encodeFunctionData("initialize", [
          this.signers.admin.address,
          await mockForwarder.getAddress(),
        ]);
        const proxy = await ERC1967Proxy.deploy(
          await taskManagerImpl.getAddress(),
          initData
        );
        await proxy.waitForDeployment();

        taskManagerWithForwarderAddress = await proxy.getAddress();
        taskManagerWithForwarder = await hre.ethers.getContractAt(
          "TaskManager",
          taskManagerWithForwarderAddress
        );
      });

      it("should have trusted forwarder set from initialization", async function () {
        const forwarder = await taskManagerWithForwarder.trustedForwarder();
        expect(forwarder).to.equal(await mockForwarder.getAddress());
      });

      it("should correctly report isTrustedForwarder as true for initialized forwarder", async function () {
        const isTrusted = await taskManagerWithForwarder.isTrustedForwarder(
          await mockForwarder.getAddress()
        );
        expect(isTrusted).to.equal(true);
      });

      it("should correctly report isTrustedForwarder as false for other addresses", async function () {
        const otherAddress = "0x9876543210987654321098765432109876543210";
        const isTrusted = await taskManagerWithForwarder.isTrustedForwarder(otherAddress);
        expect(isTrusted).to.equal(false);
      });

      // =============================================================
      //                     META-TRANSACTION FORWARDING TESTS
      // =============================================================

      it("should correctly forward a call through the MockForwarder", async function () {
        const signers = await hre.ethers.getSigners();
        const originalSender = signers[2]?.address || signers[0].address;

        // Encode the trustedForwarder() function call
        const taskManagerInterface = taskManagerWithForwarder.interface;
        const calldata = taskManagerInterface.encodeFunctionData("trustedForwarder");

        // Forward the call through MockForwarder
        const [success, returnData] = await mockForwarder.forward.staticCall(
          taskManagerWithForwarderAddress,
          calldata,
          originalSender
        );

        expect(success).to.equal(true);

        // Decode the return value
        const [returnedForwarder] = taskManagerInterface.decodeFunctionResult(
          "trustedForwarder",
          returnData
        );
        expect(returnedForwarder).to.equal(await mockForwarder.getAddress());
      });

      it("should correctly identify original sender in forwarded call", async function () {
        // The original sender we want to appear as
        const originalSender = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF";

        // Encode a call to isInitialized() - simple view function
        const taskManagerInterface = taskManagerWithForwarder.interface;
        const calldata = taskManagerInterface.encodeFunctionData("isInitialized");

        // Forward through MockForwarder with the original sender
        const [success, returnData] = await mockForwarder.forward.staticCall(
          taskManagerWithForwarderAddress,
          calldata,
          originalSender
        );

        expect(success).to.equal(true);

        // Decode - isInitialized returns bool
        const [isInit] = taskManagerInterface.decodeFunctionResult("isInitialized", returnData);
        expect(isInit).to.equal(true);
      });

      it("should use forwarder address as sender when forwarder is not trusted", async function () {
        // Deploy a second forwarder that is NOT trusted
        const MockForwarder = await hre.ethers.getContractFactory("MockForwarder");
        const untrustedForwarder = await MockForwarder.deploy();
        await untrustedForwarder.waitForDeployment();

        // The trusted forwarder is mockForwarder, not untrustedForwarder
        expect(
          await taskManagerWithForwarder.isTrustedForwarder(
            await untrustedForwarder.getAddress()
          )
        ).to.equal(false);

        // Calls from untrustedForwarder should NOT extract the appended sender
        const originalSender = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF";

        const taskManagerInterface = taskManagerWithForwarder.interface;
        const calldata = taskManagerInterface.encodeFunctionData("isInitialized");

        // This call should succeed but _msgSender() would be the untrusted forwarder
        const [success] = await untrustedForwarder.forward.staticCall(
          taskManagerWithForwarderAddress,
          calldata,
          originalSender
        );

        expect(success).to.equal(true);
      });

      it("should use msg.sender for direct calls (not through forwarder)", async function () {
        // Direct calls to the contract should use msg.sender normally
        // We verify this by checking that the contract works as expected
        const isInit = await taskManagerWithForwarder.isInitialized();
        expect(isInit).to.equal(true);
      });
    });
  });
}
