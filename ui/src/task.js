import { mapState } from "vuex";
import {
  TaskService,
  UtilService,
  QueryParamService,
} from "@nethserver/ns8-ui-lib";

export default {
  mixins: [TaskService, UtilService, QueryParamService],
  computed: { ...mapState(["instanceName", "core"]) },
  methods: {
    task(action, data = {}) {
      return new Promise((resolve, reject) => {
        const eventId = this.getUuid();
        const bus = this.core.$root;
        const events = ["completed", "aborted", "validation-failed"].map(
          (event) => `${action}-${event}-${eventId}`
        );
        const cleanup = () => {
          clearTimeout(timer);
          events.forEach((event) => bus.$off(event));
        };
        const timer = setTimeout(() => {
          cleanup();
          reject(new Error(this.$t("c.timeout")));
        }, 180000);
        bus.$once(events[0], (_context, result) => {
          cleanup();
          resolve(result.output);
        });
        const failed = (result) => {
          cleanup();
          reject(
            new Error(
              result?.error || result?.message || this.$t("c.taskError")
            )
          );
        };
        bus.$once(events[1], (_context, result) => failed(result));
        // NS8 passes the list of field errors as the first argument.
        bus.$once(events[2], (validation) => {
          cleanup();
          const error = new Error(this.$t("c.validationFailed"));
          error.validation = Array.isArray(validation) ? validation : [];
          reject(error);
        });
        this.createModuleTaskForApp(this.instanceName, {
          action,
          data,
          extra: { title: action, isNotificationHidden: true, eventId },
        }).catch((error) => {
          cleanup();
          reject(error);
        });
      });
    },
  },
};
