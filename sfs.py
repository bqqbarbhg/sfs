from abc import abstractmethod
from subprocess import Popen, PIPE
from typing import List, Union, Tuple, NamedTuple, Optional, Iterator
import shlex
import sys
import re
import json
import shutil
import os
import glob
import stat

g_git = "git"
g_verbose = False
g_show_stderr = False
g_git_version = None

def verbose(line: str):
    if g_verbose:
        print(f".. {line}")

def info(line: str):
    print(line, file=sys.stderr)

class ConfigError(Exception):
    pass

class ReturnCodeError(Exception):
    def __init__(self, message, code, stderr):
        super().__init__(message)
        self.code = code
        self.stderr = stderr

class BadGitVersionError(Exception):
    pass

class TempExistsError(Exception):
    pass

def exec_cmd(*args: str, **kwargs) -> str:
    cwd = kwargs.get("cwd", "")
    cmd = cwd + "$ " + " ".join(shlex.quote(arg) for arg in args)
    verbose(cmd)
    process = Popen(args, stdout=PIPE, stderr=PIPE, **kwargs)
    stdout, stderr = process.communicate()
    stdout = stdout.decode("utf-8", errors="ignore").strip()
    stderr = stderr.decode("utf-8", errors="ignore").strip()
    if g_show_stderr and stderr:
        print(stderr)
    if process.returncode != 0:
        raise ReturnCodeError(cmd + "\n" + stderr, process.returncode, stderr)
    return stdout

def exec_cmd_lines(*args: str, **kwargs) -> List[str]:
    return exec_cmd(*args, **kwargs).splitlines()

def exec_git(*args: str, **kwargs) -> Union[str, List[str]]:
    return exec_cmd(g_git, *args, **kwargs)

def exec_git_lines(*args: str, **kwargs) -> Union[str, List[str]]:
    return exec_cmd_lines(g_git, *args, **kwargs)

def get_git_version() -> Tuple[int, int, int]:
    version = exec_git("version")
    m = re.match(r"git version (\d+)\.(\d+)\.(\d+)", version)
    if not m:
        raise BadGitVersionError("Could not parse git version")
    return tuple(int(t) for t in m.groups())

class Desc(NamedTuple):
    ctx: str
    dict: dict

def fmt_type(obj):
    if obj is None: return "null"
    return type(obj).__name__

def parse_str(desc: Desc, name: str, default: Optional[str] = None):
    if name not in desc.dict:
        if default is not None: return default
        raise ConfigError(f"{desc.ctx}: Expected string {name}")
    value = desc.dict[name]
    if not isinstance(value, str):
        raise ConfigError(f"{desc.ctx}: Expected {name} to be a string, got {fmt_type(value)}")
    return value

def parse_list(desc: Desc, name: str, default = None):
    if name not in desc.dict:
        if default is not None: return default
        raise ConfigError(f"{desc.ctx}: Expected list {name}")
    value = desc.dict[name]
    if not isinstance(value, list):
        raise ConfigError(f"{desc.ctx}: Expected {name} to be a list, got {fmt_type(value)}")
    return value

def parse_bool(desc: Desc, name: str, default = None):
    if name not in desc.dict:
        if default is not None: return default
        raise ConfigError(f"{desc.ctx}: Expected boolean {name}")
    value = desc.dict[name]
    if not isinstance(value, bool):
        raise ConfigError(f"{desc.ctx}: Expected {name} to be a boolean, got {fmt_type(value)}")
    return value

def files_equal(path_a: str, path_b: str, binary: bool) -> bool:
    with open(path_a, "rb") as file_a:
        data_a = file_a.read()
    with open(path_b, "rb") as file_b:
        data_b = file_b.read()
    if not binary:
        data_a = data_a.replace(b"\r\n", b"\n")
        data_b = data_b.replace(b"\r\n", b"\n")
    return data_a == data_b

def data_lf_is_dos(data: bytes) -> bool:
    lf = data.count(b"\n")
    crlf = data.count(b"\r\n")
    return crlf >= lf // 2

def file_lf_is_dos(path: str) -> bool:
    with open(path, "rb") as f:
        data = f.read()
    return data_lf_is_dos(data)

def file_lf_replace(path: str, dos: bool) -> bool:
    with open(path, "rb") as f:
        data = f.read()
    if data_lf_is_dos(data) == dos:
        return
    mode = "dos" if dos else "unix"
    verbose(f"Converting {path} line endings to {mode}")
    if dos:
        data = re.sub(rb"(?<!\r)\n", b"\r\n", data)
    else:
        data = data.replace(b"\r\n", b"\n")
    with open(path, "wb") as f:
        f.write(data)

def file_num_conflicts(path: str) -> int:
    with open(path, "rb") as f:
        data = f.read()
    return data.count(b"<<<<<<<")

def remove_directory(path: str):
    verbose(f"Removing directory {path}")
    def onerror(func, path, exc_info):
        if not os.access(path, os.W_OK):
            os.chmod(path, stat.S_IWUSR)
            func(path)
        else:
            raise
    shutil.rmtree(path, onerror=onerror)

class Config:
    dependencies: List["Dependency"]

    def __init__(self, desc: Desc, path: str):
        name = os.path.basename(path)
        self.dir = os.path.dirname(path)
        self.lockfile = self.rel_path(parse_str(desc, "lockfile", f"{name}.lock"))
        self.tmp_dir = self.rel_path(parse_str(desc, "temporaryDirectory", "sfs-tmp"))
        deps = parse_list(desc, "dependencies", [])
        self.dependencies = []

        for ix, dep in enumerate(deps):
            ctx = f"dependencies[{ix}]"
            if not isinstance(dep, dict):
                raise ConfigError(f"{ctx}: Expected an object")
            dep_desc = Desc(ctx, dep)
            name = parse_str(dep_desc, "name")
            dep_desc = Desc(f"dependency {name}", dep)
            if any(c in name for c in "\r\n ="):
                raise ConfigError(f"{dep_desc.ctx}: forbidden character in name")
            dep_type = parse_str(dep_desc, "type", "git")
            dep_factory = dependency_types[dep_type]
            if not dep_factory:
                raise ConfigError(f"{ctx}: Unknown type '{dep_type}'")
            self.dependencies.append(dep_factory(name, dep_desc))

    def rel_path(self, path):
        return os.path.join(self.dir, path)

class CloneInput(NamedTuple):
    path: str
    version: Optional[str]
    exact: bool

class FileSpec(NamedTuple):
    local: str
    remote: str
    binary: bool

class CloneResult(NamedTuple):
    version: str
    files: List[FileSpec]

class Dependency:
    def __init__(self, name: str, desc: Desc):
        self.name = name
        self.root = parse_str(desc, "root", "")
        self.remote_root = parse_str(desc, "remoteRoot", "")
        files = desc.dict.get("files", [])
        root = FileSpec(local=self.root, remote=self.remote_root, binary=False)
        self.files = list(parse_filespec(f"{desc.ctx} files", root, files))

    @abstractmethod
    def clone(self, input: CloneInput) -> CloneResult:
        ...

class GitDependency(Dependency):
    def __init__(self, name: str, desc: Desc):
        super().__init__(name, desc)
        self.url = parse_str(desc, "url")
        self.branch = parse_str(desc, "branch", "")

    def clone(self, input: CloneInput) -> CloneResult:
        def local_git(*args: str, **kwargs) -> str:
            return exec_git(*args, cwd=input.path, **kwargs)
        def local_git_lines(*args: str, **kwargs) -> str:
            return exec_git_lines(*args, cwd=input.path, **kwargs)

        os.mkdir(input.path)
        local_git("init")
        local_git("remote", "add", "origin", self.url)

        version = input.version
        if not version:
            if not self.branch:
                main_branch = "master"
                for line in local_git_lines("remote", "show", "origin"):
                    m = re.search(r"HEAD branch: ?([^\r\n]+)", line)
                    if m:
                        main_branch = m.group(1)
                        verbose(f"Detected main branch '{main_branch}'")
                        break
                version = main_branch
            else:
                version = self.branch

        filter = []
        if g_git_version >= (2,25):
            filter = ["--filter=blob:none"]
            local_git("config", "--local", "extensions.partialClone", "origin")

        local_git("fetch", "--depth=1", *filter, "origin", version)
        new_version = local_git("rev-parse", "FETCH_HEAD")
        verbose(f"At commit {new_version}")

        files = []
        for filespec in self.files:
            try:
                local_git("checkout", new_version, "--", filespec.remote)
                if "*" in filespec.remote:
                    assert filespec.remote.count("*") == 1
                    assert filespec.local.count("*") == 1
                    remote_index = filespec.remote.index("*")
                    local_index = filespec.local.index("*")
                    remote_pre, remote_post = filespec.remote[:remote_index], filespec.remote[remote_index+1:]
                    local_pre, local_post = filespec.local[:local_index], filespec.local[local_index+1:]
                    for file in glob.iglob(os.path.join(input.path, filespec.remote)):
                        remote = os.path.relpath(file, input.path)
                        local = local_pre + remote[len(remote_pre):-len(remote_post)] + local_post
                        spec = filespec._replace(remote=remote, local=local)
                        files.append(spec)
                else:
                    files.append(filespec)
            except ReturnCodeError as err:
                if "did not match any file" in err.stderr:
                    continue
                raise err

        return CloneResult(version=new_version, files=files)

def join_path(a: str, b: str) -> str:
    if a.endswith("/"): a = a[:-1]
    if b.startswith("/"): b = b[1:]
    if not a: return b
    if not b: return a
    return a + "/" + b

def parse_filespec(ctx: str, parent: FileSpec, info) -> Iterator[FileSpec]:
    if isinstance(info, str):
        local = join_path(parent.local, info)
        remote = join_path(parent.remote, info)
        yield parent._replace(local=local, remote=remote)
    elif isinstance(info, dict):
        desc = Desc(ctx, info)
        binary = parse_bool(desc, "binary", parent.binary)
        parent = parent._replace(binary=binary)
        if "name" in info:
            name = parse_str(desc, "name")
            local = join_path(parent.local, name)
            remote = join_path(parent.remote, name)
            return parent._replace(local=local, remote=remote)
        elif "local" in info or "remote" in info:
            local = join_path(parent.local, parse_str(desc, "local"))
            remote = join_path(parent.remote, parse_str(desc, "remote"))
            return parent._replace(local=local, remote=remote)
        else:
            local = join_path(parent.local, parse_str(desc, "root", ""))
            remote = join_path(parent.remote, parse_str(desc, "remoteRoot", ""))
            parent = parent._replace(local=local, remote=remote)
            yield from parse_filespec(ctx, parent, info.get("files", []))
    elif isinstance(info, list):
        for item in info:
            yield from parse_filespec(ctx, parent, item)
    else:
        raise ConfigError(f"{ctx}: Bad file spec type {fmt_type(info)}")

dependency_types = {
    "git": GitDependency,
}

def do_update(argv, config: Config):
    deps = { }
    if argv.all:
        deps = { dep.name: "" for dep in config.dependencies }
    for dep in argv.dependencies:
        if "=" in dep:
            name, version = dep.split("=", maxsplit=1)
            deps[name] = version
        else:
            deps[dep] = ""

    if not deps:
        info("No dependencies listed, list dependencies or use '--all' to update everything")

    locks = {}
    try:
        with open(config.lockfile, "rt", encoding="utf-8") as f:
            for line in f.readlines():
                name, version = line.split("=", maxsplit=1)
                locks[name.strip()] = version.strip()
    except FileNotFoundError:
        pass

    tmp_dir = config.tmp_dir
    if os.path.exists(tmp_dir) and argv.remove_temp:
        remove_directory(tmp_dir)
    
    old_dir = os.path.join(tmp_dir, "old")
    new_dir = os.path.join(tmp_dir, "new")

    try:
        os.mkdir(tmp_dir)
    except FileExistsError:
        raise TempExistsError(f"Temporary directory {tmp_dir} exists, delete it or use '--remove-temp' to automatically remove it")

    os.mkdir(old_dir)
    os.mkdir(new_dir)

    dst_dir = config.dir

    for dep in config.dependencies:
        if dep.name not in deps: continue
        version = deps[dep.name]
        
        old_dep_dir = os.path.join(old_dir, dep.name)
        new_dep_dir = os.path.join(new_dir, dep.name)

        lock = locks.get(dep.name)
        if lock is not None:
            verbose(f"-- Cloning old {dep.name}")
            old_result = dep.clone(CloneInput(path=old_dep_dir, version=lock, exact=True))
        else:
            old_result = None

        verbose(f"-- Cloning new {dep.name}")
        new_result = dep.clone(CloneInput(path=new_dep_dir, version=version, exact=False))

        if old_result and new_result.version == old_result.version:
            info(f"{dep.name}: Already up to date at {new_result.version}")
            continue
        else:
            info(f"{dep.name}: Updating to {new_result.version}")

        modified_files = set()

        if old_result:
            for file in old_result.files:
                local_path = os.path.join(dst_dir, file.local)
                remote_path = os.path.join(old_dep_dir, file.remote)
                if os.path.exists(local_path) and not files_equal(local_path, remote_path, file.binary):
                    modified_files.add(file.local)

        if modified_files and not (argv.merge or argv.overwrite):
            info("WARNING: Not updated! Files modified locally (specify '--merge' or '--overwrite' to resolve):")
            for file in modified_files:
                info(f"  {file}")
            continue

        for file in new_result.files:
            local_path = os.path.join(dst_dir, file.local)
            new_path = os.path.join(new_dep_dir, file.remote)
            if os.path.exists(local_path) and files_equal(local_path, new_path, file.binary):
                continue
            if file.local in modified_files and argv.merge:
                verbose(f"Merging file {local_path}")
                old_path = os.path.join(old_dep_dir, file.remote)

                dos = file_lf_is_dos(local_path)
                file_lf_replace(old_path, dos)
                file_lf_replace(new_path, dos)

                try:
                    exec_git("merge-file", local_path, old_path, new_path)
                    info(f"  Merged {file.local} cleanly")
                except ReturnCodeError:
                    info(f"  Merged {file.local}, {file_num_conflicts(local_path)} conflicts remaining")
            else:
                verbose(f"Copiying file {file.local}")
                if file.local in modified_files:
                    info(f"  Overwriting local changes in {file.local}")
                else:
                    if os.path.exists(local_path):
                        info(f"  Updated {file.local}")
                    else:
                        info(f"  Added {file.local}")
                shutil.copyfile(new_path, local_path)
        
        locks[dep.name] = new_result.version

    with open(config.lockfile, "wt", encoding="utf-8") as f:
        for dep in config.dependencies:
            version = locks.get(dep.name)
            if not version: continue
            print(f"{dep.name}={version}", file=f)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser("sfs.py")
    parser.add_argument("--git", default="git", help="Git executable path")
    parser.add_argument("--verbose", action="store_true", help="Print verbose information")
    parser.add_argument("--show-stderr", action="store_true", help="Show stderr of ran commands")
    parser.add_argument("--keep-temp", action="store_true", help="Retain the temporary directory")
    parser.add_argument("--remove-temp", action="store_true", help="Remove exiting temporary directory")
    parser.add_argument("--config", "-c", default="sfs-deps.json", help="Configuration .json file path")

    subparsers = parser.add_subparsers(metavar="cmd")

    parser_update = subparsers.add_parser("update", help="Update files")
    parser_update.add_argument("dependencies", nargs="*", help="Dependencies to update")
    parser_update.add_argument("--all", action="store_true", help="Update all dependencies")
    parser_update.add_argument("--merge", action="store_true", help="Merge locally modified files")
    parser_update.add_argument("--overwrite", action="store_true", help="Overwrite locally modified files")
    parser_update.set_defaults(func=do_update)

    parser_revert = subparsers.add_parser("revert", help="Revert files")

    argv = parser.parse_args()

    g_git = argv.git
    g_verbose = argv.verbose
    g_show_stderr = argv.show_stderr

    g_git_version = get_git_version()
    verbose(f"Found git version {'.'.join(str(v) for v in g_git_version)}")

    with open(argv.config, "rt") as config_file:
        config_json = json.load(config_file)
    
    desc = Desc("configuration", config_json)
    config = Config(desc, argv.config)
    tmp_dir = config.tmp_dir

    try:
        argv.func(argv, config)
    except Exception as e:
        if os.path.exists(tmp_dir) and not argv.keep_temp:
            remove_directory(tmp_dir)
        raise e

    if os.path.exists(tmp_dir) and not argv.keep_temp:
        remove_directory(tmp_dir)
