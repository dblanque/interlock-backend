# Test Guidelines

- Use mocker, patch, etc. from pytest_mock (MockerFixture).
- Do not use any default unittests imports.
- Local Mocks within tests must start with `m_` prefix
- Whole-File scope Mocks must start with `f_` prefix
- Global or higher level mocks must start with `g_` prefix
- If tests are created within classes, create methods with `@staticmethod` decorators to avoid the self arg passthrough, unless there is some use for it.
- Type-hint as much as possible.
