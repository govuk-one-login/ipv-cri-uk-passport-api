package uk.gov.di.ipv.cri.passport.acceptance_tests.utilities;

import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.edge.EdgeDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.ie.InternetExplorerDriver;
import org.openqa.selenium.safari.SafariDriver;

import java.util.concurrent.ConcurrentHashMap;

public class Driver {
    private static final ConcurrentHashMap<Long, WebDriver> drivers = new ConcurrentHashMap<>();

    static {
        Runtime.getRuntime().addShutdownHook(new Thread(Driver::closeAllDrivers));
    }

    private Driver() {}

    public static WebDriver get() {
        return drivers.computeIfAbsent(Thread.currentThread().threadId(), id -> createDriver());
    }

    private static WebDriver createDriver() {
        String browser = ConfigurationReader.getBrowser();
        return switch (browser) {
            case "chrome" -> {
                setChromeProperties();
                ChromeOptions opts = new ChromeOptions();
                opts.addArguments("--remote-allow-origins=*");
                yield new ChromeDriver(opts);
            }
            case "chrome-headless" -> {
                setChromeProperties();
                ChromeOptions opts = new ChromeOptions();
                opts.addArguments("--remote-allow-origins=*");
                opts.addArguments("--headless");
                if (ConfigurationReader.noChromeSandbox()) {
                    opts.addArguments("--no-sandbox");
                    opts.addArguments("--whitelisted-ips= ");
                    opts.addArguments("--disable-dev-shm-usage");
                    opts.addArguments("--remote-debugging-port=9222");
                    opts.addArguments("start-maximized");
                    opts.addArguments("disable-infobars");
                    opts.addArguments("--disable-extensions");
                }
                yield new ChromeDriver(opts);
            }
            case "firefox" -> new FirefoxDriver();
            case "firefox-headless" -> {
                FirefoxOptions opts = new FirefoxOptions();
                opts.addArguments("-headless");
                yield new FirefoxDriver(opts);
            }
            case "ie" -> {
                if (!System.getProperty("os.name").toLowerCase().contains("windows"))
                    throw new WebDriverException("Your OS doesn't support Internet Explorer");
                yield new InternetExplorerDriver();
            }
            case "edge" -> {
                if (!System.getProperty("os.name").toLowerCase().contains("windows"))
                    throw new WebDriverException("Your OS doesn't support Edge");
                yield new EdgeDriver();
            }
            case "safari" -> {
                if (!System.getProperty("os.name").toLowerCase().contains("mac"))
                    throw new WebDriverException("Your OS doesn't support Safari");
                yield new SafariDriver();
            }
            default -> throw new WebDriverException("Unknown browser type");
        };
    }

    public static void closeAllDrivers() {
        var iterator = drivers.entrySet().iterator();
        while (iterator.hasNext()) {
            WebDriver driver = iterator.next().getValue();
            iterator.remove();
            try {
                driver.quit();
            } catch (Exception _) {
                /* Intended */
            }
        }
    }

    private static void setChromeProperties() {
        System.setProperty("webdriver.chrome.logfile", "chromedriver.log");
        System.setProperty("webdriver.chrome.verboseLogging", "true");
    }
}
