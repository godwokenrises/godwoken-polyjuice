pragma solidity ^0.8.4;

contract DebugAAA {
    uint public state = 1;

    function test() external {
        state = 2;
        revert();
    }
}

contract DebugBBB {
    uint public x = 1;

    function test(DebugAAA a) external returns (uint) {
        x = 3;
        try a.test() {
            x = 4;
            return 8;
        } catch {
            x = 2;
            return 9;
        }
    }
}

contract DebugCCC {
    uint public y = 1;

    function test(DebugBBB b, DebugAAA a) external returns (uint) {
        y = 3;
        try b.test(a) {
            y = 4;
            return 8;
        } catch {
            y = 2;
            return 9;
        }
    }
}

contract NormalRevert {
    uint public z = 1;

    function test(DebugAAA a) external returns (uint) {
        z = 3;
        a.test();
        return 9;
    }
}
