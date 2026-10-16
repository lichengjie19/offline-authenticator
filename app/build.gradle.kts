import java.util.Properties

plugins { id("com.android.application") }
val signing = Properties()
val signingFile = rootProject.file("signing.properties")
if (signingFile.exists()) signingFile.inputStream().use { signing.load(it) }
android {
    namespace = "com.chengjieli.offlineauth"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.chengjieli.offlineauth"
        minSdk = 26
        targetSdk = 36
        versionCode = 2
        versionName = "1.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildFeatures { buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    if (signingFile.exists()) signingConfigs.create("localRelease") {
        storeFile = rootProject.file(signing.getProperty("storeFile"))
        storePassword = signing.getProperty("storePassword")
        keyAlias = signing.getProperty("keyAlias")
        keyPassword = signing.getProperty("keyPassword")
    }
    buildTypes {
        debug { applicationIdSuffix = ".debug"; versionNameSuffix = "-debug" }
        release {
            isMinifyEnabled = false
            if (signingFile.exists()) signingConfig = signingConfigs.getByName("localRelease")
        }
    }
    testOptions { unitTests.isReturnDefaultValues = true }
    lint { abortOnError = true }
}
dependencies {
    implementation("com.google.zxing:core:3.5.4")
    implementation("androidx.activity:activity:1.10.1")
    implementation("androidx.camera:camera-core:1.5.3")
    implementation("androidx.camera:camera-camera2:1.5.3")
    implementation("androidx.camera:camera-lifecycle:1.5.3")
    implementation("androidx.camera:camera-view:1.5.3")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
}
