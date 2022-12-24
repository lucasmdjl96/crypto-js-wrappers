plugins {
    kotlin("js") version "1.7.20"
}

group = "io.github.lucasmdjl96"
version = "0.0.1"

repositories {
    mavenCentral()
}

kotlin {
    js(BOTH) {
        browser()
        nodejs()
    }
}

dependencies {
    api(npm("crypto-js", "4.1.1"))
    testImplementation(kotlin("test"))
    testImplementation("org.jetbrains.kotlin-wrappers:kotlin-js:1.0.0-pre.458")
}
