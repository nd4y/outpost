# Public v1 compatibility fixture

[Русский](README.ru.md)

This small independent kit was created by the unmodified file-kit implementation at commit `3193619e23a532041ad5b75376d052fb1306247b`, before typed directory/link descriptors were added. The old standalone CLI restored it successfully. `manifest.fixture` records the expected version, plaintext and SHA-256; the new reader checks those fixed bytes in `TestFrozenV1KitCreatedByPreviousImplementation`. Native fixture files preserve the original bytes: tests copy `kit/root.fixture` to the required `kit.json` name without reserializing its signed representation.

All content and recovery material here are public synthetic test data. The fixture deliberately uses a fixed master consisting of 32 bytes `0x2a` and a signing seed consisting of 32 bytes `0x37`; it contains no production secrets or source data. `teststore.PublicV1Owner` reconstructs recovery material from these documented public constants. No ready-made key file is committed. The CLI test writes a temporary recovery document with private permissions; it contains no signing key.

The original names include Unicode and two hard-link aliases. Numeric ownership and timestamps record the producer's synthetic process environment; content verification is portable, while applying those numeric attributes requires the appropriate local permissions. Independent restore is tested separately with locally created fixtures. Do not regenerate this fixture with the current reader to make a compatibility failure pass.
