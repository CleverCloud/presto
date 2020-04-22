/*
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
package com.facebook.presto.plugin.base.security;

import com.clevercloud.biscuit.error.Error;
import com.clevercloud.biscuit.token.Biscuit;
import com.clevercloud.biscuit.token.Verifier;
import com.clevercloud.biscuit.token.builder.Fact;
import com.clevercloud.biscuit.token.builder.Predicate;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.connector.ConnectorAccessControl;
import com.facebook.presto.spi.connector.ConnectorTransactionHandle;
import com.facebook.presto.spi.security.AccessControlContext;
import com.facebook.presto.spi.security.AccessDeniedException;
import com.facebook.presto.spi.security.ConnectorIdentity;
import io.vavr.control.Either;

import javax.inject.Inject;

import java.util.Arrays;
import java.util.Base64;
import java.util.Set;

import static com.clevercloud.biscuit.token.builder.Utils.caveat;
import static com.clevercloud.biscuit.token.builder.Utils.fact;
import static com.clevercloud.biscuit.token.builder.Utils.pred;
import static com.clevercloud.biscuit.token.builder.Utils.rule;
import static com.clevercloud.biscuit.token.builder.Utils.s;
import static com.clevercloud.biscuit.token.builder.Utils.string;
import static com.clevercloud.biscuit.token.builder.Utils.var;
import static io.vavr.API.Left;
import static io.vavr.API.Right;

public class BiscuitAccessControl
        implements ConnectorAccessControl
{
    private final String sealingKey;

    @Inject
    public BiscuitAccessControl(BiscuitAccessControlConfig config)
    {
        this.sealingKey = config.getSealingKey();
    }

    @Override
    public void checkCanSelectFromColumns(ConnectorTransactionHandle transactionHandle, ConnectorIdentity identity, AccessControlContext context, SchemaTableName tableName, Set<String> columnNames)
    {
        if (identity.getPrincipal().isPresent()) {
            String role = identity.getPrincipal().get().getName();
            if (!role.startsWith("biscuit:")) {
                throw new AccessDeniedException(String.format("role [%s] doesn't start with biscuit:", role));
            }

            Either<Error, Verifier> res = verifierFromBiscuit(role);
            if (res.isLeft()) {
                throw new AccessDeniedException(res.getLeft().toString());
            }

            String[] topicName = tableName.getTableName().split("/");
            String tenant = topicName[0];
            String namespace = topicName[1];
            String topic = topicName[2];

            String subscription = "presto";

            Verifier verifier = res.get();

            verifier.add_fact(topic(tenant, namespace, topic));
            verifier.add_operation("consume");
            verifier.add_fact(subscription(tenant, namespace, topic, subscription));
            verifier.set_time();

            // add these rules because there are two ways to verify that we can consume: with a right defined on the topic
            // or one defined on the subscription
            verifier.add_rule(rule("can_consume", Arrays.asList(s("authority"), s("topic"), string(tenant), string(namespace), string(topic)),
                    Arrays.asList(
                            topicSubscriptionRight(tenant, namespace, topic, subscription, "consume"))));

            verifier.add_rule(rule("can_consume", Arrays.asList(s("authority"), s("topic"), string(tenant), string(namespace), string(topic)),
                    Arrays.asList(
                            topicRight(tenant, namespace, topic, "consume"))));

            verifier.add_caveat(caveat(rule(
                    "checked_consume_right",
                    Arrays.asList(s("topic"), string(tenant), string(namespace), string(topic), s("consume")),
                    Arrays.asList(
                            pred("can_consume", Arrays.asList(s("authority"), s("topic"), string(tenant), string(namespace), string(topic)))))));

            Either verifierResult = verifier.verify();
            if (verifierResult.isLeft()) {
                throw new AccessDeniedException(String.format("consumer verifier failure: {%s}", verifierResult.getLeft()));
            }
        }
        else {
            throw new AccessDeniedException("ConnectorIdentity has no principal.");
        }
    }

    public Either<Error, Verifier> verifierFromBiscuit(String role)
    {
        Either<Error, Biscuit> deser = Biscuit.from_sealed(
                Base64.getDecoder().decode(role.substring("biscuit:".length())),
                this.sealingKey.getBytes());
        if (deser.isLeft()) {
            Error e = deser.getLeft();
            return Left(e);
        }

        Biscuit token = deser.get();

        Either<Error, Verifier> res = token.verify_sealed();
        if (res.isLeft()) {
            return res;
        }

        Verifier verifier = res.get();
        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("lookup")),
                Arrays.asList(pred("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("produce"))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("lookup")),
                Arrays.asList(pred("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("lookup")),
                Arrays.asList(pred("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"), var(3))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("produce")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("produce"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("consume"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"), var(3)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("namespace"), var(0), var(1), s("consume"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))),
                        pred("subscription", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("produce")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume")),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))))));

        verifier.add_rule(rule("right", Arrays.asList(s("authority"), s("topic"), var(0), var(1), var(2), s("consume"), var(1)),
                Arrays.asList(
                        pred("right", Arrays.asList(s("authority"), s("admin"))),
                        pred("topic", Arrays.asList(s("ambient"), var(0), var(1), var(2))),
                        pred("subscription", Arrays.asList(s("ambient"), var(0), var(1), var(2), var(3))))));

        return Right(verifier);
    }

    private Fact topic(String tenant, String namespace, String topic)
    {
        return fact("topic", Arrays.asList(s("ambient"),
                string(tenant), string(namespace), string(topic)));
    }

    private Fact subscription(String tenant, String namespace, String topic, String subscription)
    {
        return fact("subscription", Arrays.asList(s("ambient"),
                string(tenant), string(namespace), string(topic), string(subscription)));
    }

    private Predicate topicRight(String tenant, String namespace, String topic, String right)
    {
        return pred("right", Arrays.asList(s("authority"), s("topic"),
                string(tenant), string(namespace), string(topic), s(right)));
    }

    private Predicate topicSubscriptionRight(String tenant, String namespace, String topic, String subscription,
                                             String right)
    {
        return pred("right", Arrays.asList(s("authority"), s("topic"),
                string(tenant), string(namespace), string(topic), s(right), string(subscription)));
    }
}
