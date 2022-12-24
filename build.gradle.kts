plugins {
    kotlin("multiplatform") version "1.7.20"
    id("convention.publication")
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
    sourceSets {
        val jsMain by getting {
            dependencies {
                api(npm("crypto-js", "4.1.1"))
            }
        }
        val jsTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation("org.jetbrains.kotlin-wrappers:kotlin-js:1.0.0-pre.458")
            }
        }
    }
}
