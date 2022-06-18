# Rules periphery contracts

The Account and Proxy contracts used by rules

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

The account contract is inspired by [argentlabs/argent-contracts-starknet](https://github.com/argentlabs/argent-contracts-starknet)
