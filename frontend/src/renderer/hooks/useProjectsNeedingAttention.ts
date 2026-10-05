import { useQuery } from "@tanstack/react-query";
import {
	attentionNotificationsQueryKey,
	fetchAttentionNotifications,
	projectIdsNeedingAttention,
} from "../lib/notifications";

const NO_PROJECTS: ReadonlySet<string> = new Set();

/**
 * Projects with a session waiting on the user, derived from unresolved
 * notifications so the sidebar dot, toast, and notification center agree and
 * the dot clears exactly when AO resolves the notification. The notifications
 * transport invalidates this query on every live notification event.
 */
export function useProjectsNeedingAttention(): ReadonlySet<string> {
	const { data } = useQuery({
		queryKey: attentionNotificationsQueryKey,
		queryFn: ({ signal }) => fetchAttentionNotifications(signal),
		select: projectIdsNeedingAttention,
		retry: 1,
	});
	return data ?? NO_PROJECTS;
}
