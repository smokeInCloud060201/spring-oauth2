package org.example.authorizationserver.util;

import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.id.IdentifierGenerator;

public class SnowflakeIdGenerator implements IdentifierGenerator {

    private static final SnowflakeIdGeneratorUtil snowflakeIdGenerator = new SnowflakeIdGeneratorUtil(10L, 1L);

    @Override
    public Object generate(SharedSessionContractImplementor sharedSessionContractImplementor, Object o) {
        return snowflakeIdGenerator.generateId();
    }
}