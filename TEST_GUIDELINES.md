# Test Guidelines

- Use mocker, patch, etc. from pytest_mock (MockerFixture).
- Do not use any default unittests imports.
- Local Function Mocks within tests must start with `m_` prefix
- Non-local scope Mocks must start with `f_` prefix
- Higher Scope Factory Mocks must start with `fc_` prefix
- Global or higher level mocks must start with `g_` prefix
- Type-hint as much as possible.
