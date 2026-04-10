"""Tests for command parsers."""

from agentguard.parsers import parse_command


def test_npm_install():
    actions = parse_command("npm install lodash")
    assert len(actions) == 1
    assert actions[0].action == "install"
    assert actions[0].packages[0].name == "lodash"
    assert actions[0].packages[0].manager == "npm"


def test_npm_install_multiple():
    actions = parse_command("npm install lodash express react")
    assert len(actions) == 1
    assert len(actions[0].packages) == 3


def test_npm_install_scoped():
    actions = parse_command("npm install @angular/core")
    assert len(actions) == 1
    assert actions[0].packages[0].scope == "@angular"
    assert actions[0].packages[0].name == "core"


def test_npm_install_with_version():
    actions = parse_command("npm install lodash@4.17.21")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "lodash"
    assert actions[0].packages[0].version == "4.17.21"


def test_npm_install_dev():
    actions = parse_command("npm install -D typescript")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "typescript"


def test_pnpm_add():
    actions = parse_command("pnpm add react react-dom")
    assert len(actions) == 1
    assert len(actions[0].packages) == 2
    assert actions[0].packages[0].manager == "pnpm"


def test_yarn_add():
    actions = parse_command("yarn add express")
    assert len(actions) == 1
    assert actions[0].packages[0].manager == "yarn"


def test_pip_install():
    actions = parse_command("pip install requests")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "requests"
    assert actions[0].packages[0].manager == "pip"


def test_pip_install_with_version():
    actions = parse_command("pip install django==4.2")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "django"
    assert actions[0].packages[0].version == "4.2"


def test_pip_install_with_extras():
    actions = parse_command("pip install fastapi[all]")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "fastapi"


def test_pip3_install():
    actions = parse_command("pip3 install boto3")
    assert len(actions) == 1
    assert actions[0].packages[0].manager in ("pip", "pip3")


def test_uv_pip_install():
    actions = parse_command("uv pip install numpy pandas")
    assert len(actions) == 1
    assert len(actions[0].packages) == 2


def test_go_get():
    actions = parse_command("go get github.com/gin-gonic/gin")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "github.com/gin-gonic/gin"


def test_cargo_add():
    actions = parse_command("cargo add serde tokio")
    assert len(actions) == 1
    assert len(actions[0].packages) == 2


def test_gem_install():
    actions = parse_command("gem install rails")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "rails"


def test_git_clone():
    actions = parse_command("git clone https://github.com/user/repo.git")
    assert any(a.action == "clone" for a in actions)
    clone = [a for a in actions if a.action == "clone"][0]
    assert "https://github.com/user/repo.git" in clone.urls


def test_npx_execute():
    actions = parse_command("npx create-react-app my-app")
    assert len(actions) == 1
    assert actions[0].action == "execute"
    assert actions[0].packages[0].name == "create-react-app"


def test_curl_pipe_sh():
    actions = parse_command("curl -fsSL https://example.com/install.sh | sh")
    piped = [a for a in actions if a.is_piped_exec]
    assert len(piped) == 1


def test_chained_commands():
    actions = parse_command("npm install foo && pip install bar")
    install_actions = [a for a in actions if a.action == "install"]
    assert len(install_actions) == 2


def test_brew_install():
    actions = parse_command("brew install wget")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "wget"


def test_no_action_for_ls():
    actions = parse_command("ls -la")
    assert len(actions) == 0


def test_no_action_for_cd():
    actions = parse_command("cd /tmp")
    assert len(actions) == 0


def test_npm_ci_no_packages():
    # npm ci doesn't take package args - should parse but find no packages
    actions = parse_command("npm ci")
    # ci is in install_cmds but has no package args
    assert all(len(a.packages) == 0 for a in actions) or len(actions) == 0


def test_composer_require():
    actions = parse_command("composer require laravel/framework")
    assert len(actions) == 1
    assert actions[0].action == "install"
    assert actions[0].packages[0].name == "laravel/framework"
    assert actions[0].packages[0].manager == "composer"


def test_composer_require_with_version():
    actions = parse_command("composer require guzzlehttp/guzzle:^7.0")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "guzzlehttp/guzzle"
    assert actions[0].packages[0].version == "^7.0"


def test_composer_require_dev():
    actions = parse_command("composer require --dev phpunit/phpunit")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "phpunit/phpunit"


def test_composer_global_require():
    actions = parse_command("composer global require laravel/installer")
    assert len(actions) == 1
    assert actions[0].packages[0].name == "laravel/installer"


def test_local_path_ignored():
    actions = parse_command("npm install ./local-package")
    # Local paths should be ignored
    install_actions = [a for a in actions if a.action == "install"]
    assert all(len(a.packages) == 0 for a in install_actions) or len(install_actions) == 0
