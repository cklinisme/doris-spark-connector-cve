/*
 * Copyright 2026 Local security fork contributors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.apache.doris.shaded.com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.apache.doris.shaded.com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.doris.shaded.com.fasterxml.jackson.databind.exc.InvalidTypeIdException;
import org.apache.doris.shaded.com.fasterxml.jackson.databind.json.JsonMapper;
import org.apache.doris.shaded.com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import java.util.List;

/** Harmless regression for GHSA-j3rv-43j4-c7qm. No commands or network activity. */
public class Cve54512Regression {
    private static int instances;

    public static class Wrapper {
        @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.WRAPPER_ARRAY)
        public Object value;
    }

    public static class DeniedBean {
        public String value;
        public DeniedBean() { instances++; }
    }

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = JsonMapper.builder().polymorphicTypeValidator(
            BasicPolymorphicTypeValidator.builder()
                .allowIfSubType("java.util.ArrayList")
                .allowIfSubType("java.util.HashMap")
                .allowIfSubType("java.lang.String").build()).build();
        Wrapper allowed = mapper.readValue("{\"value\":[\"java.util.ArrayList\",[\"ok\"]]}", Wrapper.class);
        require(((List<?>) allowed.value).get(0).equals("ok"), "Allowed container must still work");
        String denied = DeniedBean.class.getName();
        String list = "{\"value\":[\"java.util.ArrayList<" + denied + ">\",[{\"value\":\"probe\"}]]}";
        if (args.length == 1 && "--expect-vulnerable".equals(args[0])) {
            require("2.13.5".equals(mapper.version().toString()), "Baseline must be original Jackson 2.13.5");
            Wrapper result = mapper.readValue(list, Wrapper.class);
            require(instances == 1 && ((DeniedBean) ((List<?>) result.value).get(0)).value.equals("probe"),
                "Baseline did not reproduce the validator bypass");
            System.out.println("BASELINE: Jackson 2.13.5 reproduced CVE-2026-54512 with a harmless bean");
            return;
        }
        require("2.18.10".equals(mapper.version().toString()), "Release must use Jackson 2.18.10");
        String[] payloads = {
            list,
            "{\"value\":[\"java.util.HashMap<java.lang.String," + denied + ">\",{\"key\":{\"value\":\"probe\"}}]}",
            "{\"value\":[\"java.util.ArrayList<java.util.ArrayList<" + denied + ">>\",[[{\"value\":\"probe\"}]]]}"
        };
        for (String payload : payloads) {
            instances = 0;
            try {
                mapper.readValue(payload, Wrapper.class);
                throw new AssertionError("Denied generic parameter was accepted");
            } catch (InvalidTypeIdException expected) {
                require(instances == 0, "Denied bean was instantiated before rejection");
            }
        }
        System.out.println("PASS: CVE-2026-54512; 3 denied generic variants rejected before bean construction; allowed control passed");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
