from app.models.linux_user import LinuxUser


def test_linux_user_model():
    user = LinuxUser(
        username="root",
        uid=0,
        gid=0,
        home="/root",
        shell="/bin/bash",
    )

    assert user.username == "root"
    assert user.uid == 0
    assert user.home == "/root"
