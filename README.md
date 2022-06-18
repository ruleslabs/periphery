# Rules account contract

The Account and Proxy contracts deployed for rules users

## Local development

### Compile contracts

```bash
nile compile --account_contract contracts/account/Account.cairo
nile compile contracts/proxy/Proxy.cairo
```

### Run tests

```bash
pytest tests/account.py
```

## Credits

These contracts are inspired by [argentlabs/argent-contracts-starknet](https://github.com/argentlabs/argent-contracts-starknet)
