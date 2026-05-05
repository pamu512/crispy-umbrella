# -*- mode: python -*-


def make_exe():
    dist = default_python_distribution()
    exe = dist.to_python_executable("cti_ml")
    exe.add_python_resources(exe.pip_install(["numpy", "scikit-learn"]))
    return exe


def make_install(exe):
    m = FileManifest()
    m.add_python_resource(".", exe)
    return m


register_target("exe", make_exe)
register_target("install", make_install, depends=["exe"], default=True)
resolve_targets()
