/* Independent test against the final shaded JAR and the actual Spark runtime. */
import org.apache.doris.shaded.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.doris.shaded.com.fasterxml.jackson.databind.json.JsonMapper;
import org.apache.doris.shaded.com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.doris.spark.client.entity.StreamLoadResponse;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.sources.DataSourceRegister;
import java.time.LocalDate;
import java.util.ServiceLoader;

public class ShadedJacksonSmoke {
    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = JsonMapper.builder().addModule(new JavaTimeModule()).build();
        require("2.18.10".equals(mapper.version().toString()), "Unexpected shaded Jackson version");
        StreamLoadResponse response = mapper.readValue(
                "{\"TxnId\":7,\"Label\":\"test\",\"Status\":\"Success\",\"NewField\":true}", StreamLoadResponse.class);
        require(response.isSuccess() && response.getTxnId() == 7, "Doris response binding failed");
        LocalDate date = LocalDate.of(2026, 9, 16);
        require(date.equals(mapper.readValue(mapper.writeValueAsString(date), LocalDate.class)), "Java time module mismatch");
        boolean registered = false;
        for (DataSourceRegister source : ServiceLoader.load(DataSourceRegister.class)) {
            if ("doris".equals(source.shortName())) registered = true;
        }
        require(registered, "Doris service registration not found");
        // Spark loads its own unrelocated Jackson/Scala module in this process.
        SparkSession spark = SparkSession.builder().master("local[1]").appName("doris-cve-smoke")
                .config("spark.ui.enabled", "false").config("spark.driver.host", "127.0.0.1").getOrCreate();
        try {
            require("3.5.1".equals(spark.version()), "Wrong Spark version");
            require(spark.range(3).count() == 3L, "Spark local job failed");
            require(spark.sql("SELECT '日本語' AS value").toJSON().first().contains("日本語"), "Spark JSON serialization failed");
        } finally { spark.stop(); }
        System.out.println("PASS: shaded Jackson 2.18.10, Doris JSON, JavaTime, service discovery, Spark 3.5.1 local job");
    }
    private static void require(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }
}
/*
 * Copyright 2026 Local security fork contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
