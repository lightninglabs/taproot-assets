INSERT INTO internal_keys VALUES(1,X'03efbcf2878876bae81ca9a7f6476764d2da38d565b9fb2b691e7bb22fd99f9e5e',212,2);

-- The NUMS key as an internal key.
INSERT INTO internal_keys VALUES(2, X'02dca094751109d0bd055d03565874e8276dd53e926b44e3bd1bb6bf4bc130a279', 212, 0);

-- This is a correct BIP-86 key.
INSERT INTO script_keys VALUES(1,1,X'029c571fffcac1a1a7cd3372bd202ad8562f28e48b90f8a4eb714eca062f576ee6',NULL,true);

-- This is not a correct BIP-86 key, it should be detected as unknown.
INSERT INTO script_keys VALUES(2,1,X'039c571fffcac1a1a7cd3372bd202ad8562f28e48b90f8a4eb714eca062f576ee6',NULL,true);

-- This should be detected as script path key.
INSERT INTO script_keys VALUES(3,1,X'03f9cdf1ff7c9fbb0ea3c8533cd7048994f41ea20a79764469c22aa18aa6696169',X'b2f0cd8ecb23c1710903f872c31b0fd37e15224af457722a87c5e0c7f50fffb3',true);

-- This should be detected as a channel key.
INSERT INTO script_keys VALUES(4,2,X'0250aaeb166f4234650d84a2d8a130987aeaf6950206e0905401ee74ff3f8d18e6',X'a85b2107f791b26a84e7586c28cec7cb61202ed3d01944d832500f363782d675',true);
